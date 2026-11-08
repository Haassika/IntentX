# Independent benign evaluation

Use the recovered model on a fresh collection with the same hardened image,
resource limits, workload settings, and declared lab hostname. Use a different
workload seed (43 rather than 42). This measures flags on a controlled benign
workload; it does not estimate real-world detection accuracy.

The model loader accepts trusted IntentX artifacts only. The evaluator never
trains or modifies the model, and records its SHA-256. It rejects incomplete
collection and unknown lab hostnames. Assigning the original lab hostname to
a fresh equivalent container is an explicit lab identity choice, not proof
that arbitrary machines are equivalent. Keep the production detector's host
restriction intact.

Build the updated image, create a fresh Docker results volume, and start the
benign workload for 20 minutes. Set `--hostname` to the hostname in the recovered
baseline manifest, and use `--seed 43`. Retain the existing read-only root,
network isolation, dropped capabilities, no-new-privileges, PID limit, CPU and
memory limits, private `/tmp` tmpfs, and persistent `/app/runtime` volume.

Copy the trusted recovered model into the running container's runtime directory
using `docker cp`. Then run a ten-minute evaluation on macOS:

```sh
caffeinate -i docker exec intentx-benign-evaluation \
  python -m intentx.behavior.evaluation \
  --model-path /app/runtime/frozen-baseline.joblib \
  --duration-seconds 600 --interval-seconds 5
```

Expected coverage: 120 resource samples and ten complete one-minute windows.
The final line names `evaluation.json`. It contains every window's score,
number of flagged windows, benign flag rate, model checksum, training sample
count, and collection coverage. A failure creates `evaluation_failure.json`
and exits unsuccessfully. Export the persistent volume using the read-only tar
helper described in BENIGN_WORKLOAD.md; results survive container shutdown.

A ten-window run is an initial check: one flag changes the rate by ten percentage
points. Review individual scores and resource context before changing thresholds.
A flag is not evidence of an intrusion. Do not tune on this run and then report
its original flag rate as independent validation.
