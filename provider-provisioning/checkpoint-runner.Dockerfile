# Provider-only Check Point runner. Build only from a context produced by
# scripts/build_checkpoint_runner_context.py, which verifies every input.
FROM mcr.microsoft.com/azurelinux/base/python:3.12@sha256:71a1f5a1821f4c56e45aff52e792ed6c0500631e201cfc140c4c9d22886b29f9 AS build
COPY wheels /build/wheels
COPY runner-requirements.lock /build/runner-requirements.lock
RUN python3 -m pip install --no-cache-dir --no-index --only-binary=:all: --require-hashes \
        --find-links /build/wheels --target /opt/faas/site -r /build/runner-requirements.lock

FROM mcr.microsoft.com/azurelinux/base/python:3.12@sha256:71a1f5a1821f4c56e45aff52e792ed6c0500631e201cfc140c4c9d22886b29f9
COPY --from=build /opt/faas/site /opt/faas/site
COPY app /opt/faas/app
COPY checkpoint /opt/faas/checkpoint
COPY checkpoint-vmss /opt/faas/checkpoint-vmss
COPY bin/terraform /opt/faas/bin/terraform
# Terraform (BSL 1.1), Check Point modules (Apache-2.0, under checkpoint/) and CFWaaS (MIT) terms.
COPY licenses /opt/faas/licenses
LABEL org.opencontainers.image.source="https://github.com/roie9876/CFWaaS" \
      org.opencontainers.image.title="cfwaas-checkpoint-runner" \
      org.opencontainers.image.description="CFWaaS Check Point provisioning runner; see /opt/faas/licenses"
# Runtime checks require root-owned, non-writable code and dependencies for the non-root runner.
RUN chown -R 0:0 /opt/faas && chmod -R a=rX /opt/faas && chmod 0555 /opt/faas/bin/terraform
ENV PYTHONPATH=/opt/faas/site PYTHONDONTWRITEBYTECODE=1
WORKDIR /opt/faas/app
USER 65532:65532
ENTRYPOINT ["python3", "-B", "-s", "-m", "service.checkpoint_runner_entry"]
