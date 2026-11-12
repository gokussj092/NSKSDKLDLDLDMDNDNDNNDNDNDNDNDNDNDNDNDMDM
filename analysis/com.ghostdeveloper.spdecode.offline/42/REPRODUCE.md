# Reproduce

Use the dependency/build commands in the two referenced intake REPRODUCE.md
files. Then, from the repository root:

```sh
python analysis/com.ghostdeveloper.spdecode.offline/42/tools/verify.py /tmp/spdecode-hc-native /tmp/spdecode-npv-native
python -m unittest tests.test_offline_share_ui_contract
```

The wrapper calls the canonical suites without duplicating fixtures.
The private HC probe is separately documented and prints no configuration.
