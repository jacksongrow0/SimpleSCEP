# syntax=docker/dockerfile:1

# Assets: Tailwind output and the copied node_modules JS that static/ is made of.
# static/ is gitignored, so it has to be built here rather than copied in.
#
# Pin both the Node patch release and the multi-platform image digest. Dependency
# automation should update these together after the replacement image is tested.
FROM node:22.23.2-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS assets

WORKDIR /src
COPY package.json package-lock.json ./
# --ignore-scripts: nothing here needs an install hook, and every dependency in
# package-lock.json is otherwise free to run arbitrary code in this stage. Tailwind
# ships its platform binaries as ordinary optional packages, so nothing is lost.
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY input.css ./
COPY assets ./assets
COPY view ./view
RUN npm run assets:build

# Pin both the Go patch release and the multi-platform image digest, the same way.
FROM golang:1.25.14-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build

WORKDIR /src
COPY go.mod go.sum ./
# verify checks every downloaded module against the hash go.sum recorded, so a
# mirror serving different bytes for a pinned version fails the build here rather
# than shipping.
RUN go mod download && go mod verify

COPY . .
RUN go tool templ generate
# No cgo, source paths, VCS stamping, symbol table, or DWARF data are needed at
# runtime. -mod=readonly makes a build that would have to edit go.mod fail instead
# of quietly resolving a dependency nobody reviewed.
RUN CGO_ENABLED=0 GOOS=linux go build \
	-mod=readonly \
	-trimpath \
	-buildvcs=false \
	-ldflags="-s -w -buildid=" \
	-o /out/simplescep \
	./cmd

# The runtime contains no shell, package manager, libc, or writable application
# files: only the static Go executable, the assets it serves, the migrations it
# applies at startup, and the CA roots needed for Resend/Cloud KMS TLS.
FROM scratch
WORKDIR /app

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65534:65534 /out/simplescep /app/simplescep
# serve() runs migrate() before it listens, and migrate() globs these off disk
# relative to the working directory. Without them the container starts against
# whatever schema the database already had and reports nothing.
COPY --chown=65534:65534 internal/database/migrations /app/internal/database/migrations
COPY --chown=65534:65534 public /app/public
COPY --from=assets --chown=65534:65534 /src/static /app/static

USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/app/simplescep", "serve"]
