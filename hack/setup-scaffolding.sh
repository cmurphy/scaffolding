#!/usr/bin/env bash
# Copyright 2022 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# Since the behaviour on oidc is different on k8s <1.23, check to see if we
# need to do some mucking with the Fulcio config
NEED_TO_UPDATE_FULCIO_CONFIG="false"
K8S_SERVER_VERSION=$(kubectl version -ojson | yq '.serverVersion.minor' -)

if [[ "${K8S_SERVER_VERSION}" == "21" ]] || [[ "${K8S_SERVER_VERSION}" == "22" ]]; then
  echo "Running on k8s 1.${K8S_SERVER_VERSION}.x will update Fulcio accordingly"
  NEED_TO_UPDATE_FULCIO_CONFIG="true"
fi

ko version
go version

debug() {
    stat ~/ko || true
    tree ~/ko || true
}
trap debug EXIT

# Install Trillian and wait for it to come up
echo '::group:: Install Trillian'
make ko-apply-trillian
echo '::endgroup::'
