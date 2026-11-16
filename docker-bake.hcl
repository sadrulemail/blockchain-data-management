# Multi-platform images with an SBOM and SLSA provenance attached.
#   docker buildx bake -f docker-bake.hcl                      build both images
#   docker buildx bake -f docker-bake.hcl --push               linux/amd64 + linux/arm64, pushed
#   VERSION=1.2.0 docker buildx bake -f docker-bake.hcl --push

variable "VERSION" { default = "1.1.0" }
variable "REGISTRY" { default = "docker.io/sadrulemail" }
variable "REVISION" { default = "" }
variable "CREATED" { default = "" }
variable "PLATFORMS" { default = "linux/amd64,linux/arm64" }

group "default" {
  targets = ["service", "contracts"]
}

target "_common" {
  context    = "."
  dockerfile = "Dockerfile"
  platforms  = split(",", PLATFORMS)
  args = {
    VERSION  = VERSION
    REVISION = REVISION
    CREATED  = CREATED
  }
  attest = [
    "type=sbom",
    "type=provenance,mode=max",
  ]
}

target "service" {
  inherits = ["_common"]
  target   = "service"
  tags     = ["${REGISTRY}/dataledger:${VERSION}", "${REGISTRY}/dataledger:latest"]
}

target "contracts" {
  inherits = ["_common"]
  target   = "contracts"
  tags     = ["${REGISTRY}/dataledger-contracts:${VERSION}", "${REGISTRY}/dataledger-contracts:latest"]
}
