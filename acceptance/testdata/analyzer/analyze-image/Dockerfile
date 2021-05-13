FROM ubuntu:bionic
ARG cnb_platform_api

RUN apt-get update && apt-get install -y ca-certificates

COPY container /

WORKDIR /layers

ENV CNB_USER_ID=2222

ENV CNB_GROUP_ID=3333

ENV CNB_PLATFORM_API=${cnb_platform_api}

RUN chown -R $CNB_USER_ID:$CNB_GROUP_ID /some-dir

RUN chown -R $CNB_USER_ID:$CNB_GROUP_ID /layers

# ensure docker config directory is root owned and NOT world readable
RUN chown -R root /docker-config; chmod -R 700 /docker-config

ARG registry

# replace company/stack -> 192.../company/stack
RUN sed -i "s/company\/stack/${registry}\/company\/stack/g" /cnb/stack.toml
RUN sed -i "s/company\/stack/${registry}\/company\/stack/g" /cnb/mismatch-stack.toml
RUN sed -i "s/company\/stack/${registry}\/company\/stack/g" /cnb/missing-build-image-stack.toml
RUN sed -i "s/company\/stack/${registry}\/company\/stack/g" /cnb/run-mirror-stack.toml
