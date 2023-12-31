## [1.1.3](https://github.com/PromH/codr/compare/1.1.2...1.1.3) (2023-11-28)


### Bug Fixes

* delete extra semantic-release-cargo step ([dc3f2da](https://github.com/PromH/codr/commit/dc3f2da2a7dc400c9e9fcd29d2d148f31e3639bc))

## [1.1.2](https://github.com/PromH/codr/compare/1.1.1...1.1.2) (2023-11-28)


### Bug Fixes

* change to use semantic-release-rust ([f977401](https://github.com/PromH/codr/commit/f977401323271573d7adf0e9a0fe35c802890468))
* revert back to semantic-release-cargo but with more debug logs ([0d8abd6](https://github.com/PromH/codr/commit/0d8abd6d0c8821ce1c185e57784df8ca07e7c774))

## [1.1.1](https://github.com/PromH/codr/compare/1.1.0...1.1.1) (2023-10-21)


### Bug Fixes

* disable aarch64-unknown-linux-gnu ([eacddce](https://github.com/PromH/codr/commit/eacddce096c7bb5fb55704df9980c6880ea2e929))
* remove napi stuff ([668b897](https://github.com/PromH/codr/commit/668b8970e4f14e243c1900cf1fac5ca1a73bd347))
* uncomment assets in .releaserc.yaml ([08fc3b1](https://github.com/PromH/codr/commit/08fc3b167d4bccf03d8314b05e245bebbd4770ca))
* update pipelines ([1fb4367](https://github.com/PromH/codr/commit/1fb43676b8a013668bd28269c233b6119f8db0a6))

# [1.1.0](https://github.com/PromH/codr/compare/1.0.7...1.1.0) (2023-10-18)


### Features

* start to prepare for github release artifacts and trigger major release to mark pipelines almost working ([f0d8ea7](https://github.com/PromH/codr/commit/f0d8ea76057dd9c4f4eb2b8cd6adf29bc48d7b53))

## [1.0.7](https://github.com/PromH/codr/compare/1.0.6...1.0.7) (2023-10-18)


### Bug Fixes

* update docs to add install instructions ([bb4a853](https://github.com/PromH/codr/commit/bb4a853ec02a989106865d12f07fbcbadbb16947))

## [1.0.6](https://github.com/PromH/codr/compare/1.0.5...1.0.6) (2023-10-18)


### Bug Fixes

* update docs in readme and attempt to trigger release again ([abb62b2](https://github.com/PromH/codr/commit/abb62b2d7ac40139e302e92f28e52c5495f85bb4))

## [1.0.5](https://github.com/PromH/codr/compare/1.0.4...1.0.5) (2023-10-17)


### Bug Fixes

* change member order of root cargo.toml ([6496364](https://github.com/PromH/codr/commit/6496364c0a06e55d0eb0e62fe2385bf61ff3dcb4))
* update toml and readme files ([ca8b1a3](https://github.com/PromH/codr/commit/ca8b1a33f11eb93f84f744fe45ca5c1a7f308056))

## [1.0.4](https://github.com/PromH/codr/compare/1.0.3...1.0.4) (2023-09-18)


### Bug Fixes

* turn on debug logs for semantic-release job ([2025112](https://github.com/PromH/codr/commit/2025112cbcd372b6e8d08b8136b8bac8ac662dee))

## [1.0.3](https://github.com/PromH/codr/compare/1.0.2...1.0.3) (2023-09-18)


### Bug Fixes

* add package.json files ([a9b2ef3](https://github.com/PromH/codr/commit/a9b2ef37a2a296daff97921f7712225f6e98f4a9))

## [1.0.2](https://github.com/PromH/codr/compare/1.0.1...1.0.2) (2023-09-15)


### Bug Fixes

* update cargo.toml files to help with semantic-release-publish ([7e3784f](https://github.com/PromH/codr/commit/7e3784fb5e42b0748393b84b4e83ff23634a7f9b))

## [1.0.1](https://github.com/PromH/codr/compare/1.0.0...1.0.1) (2023-09-15)


### Bug Fixes

* update token and retrigger release ([f50e2b0](https://github.com/PromH/codr/commit/f50e2b0659f1343c0d3d6a253f6021f602abf51c))

# 1.0.0 (2023-09-15)


### Bug Fixes

* add install for semantic release cargo ([59fd096](https://github.com/PromH/codr/commit/59fd096741a9997649dbbdb3fe60c1c2eea79e1e))
* add newline at end of yaml file ([2bee047](https://github.com/PromH/codr/commit/2bee047019d43f2179e0d4d85ca101aed5cbd62f))
* add npm install to pipeline job ([4422b42](https://github.com/PromH/codr/commit/4422b42cc03956821970b8a001f830f1dc809a94))
* add semantic-release/exec ([c84227d](https://github.com/PromH/codr/commit/c84227dc21ed807181d677f07e89ce8639745c24))
* correct bad pipeline layout ([90468dc](https://github.com/PromH/codr/commit/90468dc34821ad0e348010f18e0b4233f5d78cd4))
* fix pipeline job for caching ([166793a](https://github.com/PromH/codr/commit/166793a57dea3711982a1dc4c699f68e79b5fd08))
* increase permissions of semantic-release jobs ([0afb9b5](https://github.com/PromH/codr/commit/0afb9b57dd742054063bca2ef2e5fdc7609f6e9c))
* move npm dependencies step to separate job ([00a1c90](https://github.com/PromH/codr/commit/00a1c90a5b119e6b42d1ca0af97fced509611c88))
* remove package-lock.json hashing ([27cae97](https://github.com/PromH/codr/commit/27cae978a8e4d84bd8109cef0d63df7a668e72d0))
* resolve linting and style issues ([2a7796e](https://github.com/PromH/codr/commit/2a7796e3b6ad617d1c96e06724f3f470bb276051))
* resolve new linting errors ([7f5ac2e](https://github.com/PromH/codr/commit/7f5ac2efb20d33b3b7d11def0a53b0b591bec8f3))
* try to make job start ([6a52226](https://github.com/PromH/codr/commit/6a52226d6ed7d2c5d5ce3138a18bed8c4da0c31f))
* update releaserc ([f43b214](https://github.com/PromH/codr/commit/f43b214f28a73e27d8f5d7cb3246c6ce86ac9644))
* update releaserc plugins exec cmds ([e2cef54](https://github.com/PromH/codr/commit/e2cef5454167b465f4e8fa9551a1dbe2bfb77f6f))
* update to match expected format for pipeline ([0c3dddc](https://github.com/PromH/codr/commit/0c3dddcbb382daef37ea680e8a3bac3e79519390))
* use cargo.toml as cache for setup-node ([00b66b2](https://github.com/PromH/codr/commit/00b66b21d07141a077d593d99bd453e6eadf02db))
* use taiki-e to install semantic-release-cargo ([6802570](https://github.com/PromH/codr/commit/6802570d172de0a85919944f66dc51a06451ceda))


### Features

* add error response handling ([5468e9b](https://github.com/PromH/codr/commit/5468e9b1f9204e1e07bbb0afe04be5862e68be07))
* almost working ([072a4cf](https://github.com/PromH/codr/commit/072a4cf2d5f15d246e46789826aab4d9d941e0d5))
* implement a whole bunch of structs representing onedrive api resources ([cf3cdd0](https://github.com/PromH/codr/commit/cf3cdd0635bc249f650cf4b2227abf2e7b47a2ab))
* set up token obtainer and set up argument handling ([bc512ed](https://github.com/PromH/codr/commit/bc512ed7548829112267429a114db2191c9ffabd))
