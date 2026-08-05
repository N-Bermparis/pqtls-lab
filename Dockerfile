# syntax=docker/dockerfile:1.7
#
# The real image definition lives in docker/Dockerfile, next to the compose
# file and docker/openssl-checksums.txt.
#
# There is deliberately only ONE build definition. A second copy here would
# drift from it, and two Dockerfiles in one repository producing different
# images from the same commit is exactly the kind of irreproducibility this
# project is supposed to avoid.
#
# Build with:
#
#     docker build -f docker/Dockerfile -t pqtls-lab:local .
#
# or run the full demonstration with:
#
#     cd docker && docker compose up --build

FROM ubuntu@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

# Fail the build with an explanation rather than quietly producing an image
# that is not the one the caller wanted.
RUN <<'EOF'
cat >&2 <<'MESSAGE'

  ############################################################
  #  Wrong Dockerfile.                                       #
  #                                                          #
  #  pqtls-lab is built from docker/Dockerfile:              #
  #                                                          #
  #    docker build -f docker/Dockerfile -t pqtls-lab:local . #
  #                                                          #
  #  or, for the full demonstration:                         #
  #                                                          #
  #    cd docker && docker compose up --build                #
  ############################################################

MESSAGE
exit 1
EOF
