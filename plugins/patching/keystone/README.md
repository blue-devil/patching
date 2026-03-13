# Keystone Engine (Patching)

This IDA plugin is currently self-shipping a [fork][01] of the ubiquitous
[Keystone Engine][02] rather than using the PyPI version.

This is simply out of convenience for distributing fixes or making
breaking changes for the betterment of the plugin.

## Why is this folder empty?

The directory that you're reading this in will be populated by a GitHub
[Workflow][03] that packages the plugin for distribution.

You should always download the final, distributable version of the plugin
from the [releases][04] page of the plugin repo. If you cloned the repo
and tried to manually install the plugin, that's probably why it's
not working and you're here reading this ;-)

[01]: https://github.com/gaasedelen/keystone
[02]: https://github.com/keystone-engine/keystone
[03]: https://github.com/gaasedelen/patching/blob/main/.github/workflows/package-plugin.yaml
[04]: https://github.com/gaasedelen/patching/releases
