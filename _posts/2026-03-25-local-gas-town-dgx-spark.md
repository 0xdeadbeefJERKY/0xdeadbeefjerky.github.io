---
title: "Running Gas Town on Sparks and Fumes"
description: >
    How I replaced Claude Code with a self-hosted Qwen3-Coder-Next-FP8 model
    and OpenCode on an NVIDIA DGX Spark to run Gas Town locally, cutting API
    costs and opening the door to performance optimization.
date: 2026-03-25 10:00:00 -0500
categories: [AI, vibe coding, local lab]
tags: [gas town, dgx spark, qwen, opencode, vllm, local inference, nvidia]
toc: true
image: /assets/img/og-default.png
---

![cloudgoat](/assets/img/gastown.jpg){: .center-image}

## TL;DR

[Gas Town](https://github.com/steveyegge/gastown){:target="_blank"} is a
powerful multi-agent workspace manager, but running a swarm of parallel agents
against a cloud API burns through credits at an alarming rate. I picked up an
[NVIDIA DGX Spark](https://www.nvidia.com/en-us/products/workstations/dgx-spark/){:target="_blank"},
self-hosted the [Qwen3-Coder-Next-FP8](https://huggingface.co/Qwen/Qwen3-Coder-Next-FP8){:target="_blank"}
model using [vLLM](https://docs.vllm.ai/){:target="_blank"}, and swapped
Claude Code out for [OpenCode](https://opencode.ai/){:target="_blank"} to
serve as Gas Town's local coding agent. The result: minimal API costs per token
and a foundation I can tune and optimize over time.

## Why Go Local?

If you've spent any time with Gas Town, you know it's not shy about token
consumption. [Steve Yegge](https://steve-yegge.medium.com/welcome-to-gas-town-4f25ee16dd04){:target="_blank"}
designed it to orchestrate swarms of coding agents in parallel, with the Mayor
coordinating Polecats, the Refinery managing merge queues, and several other
specialized roles all chattering away simultaneously to keep things moving. This is incredibly
powerful, but it comes at a cost. Early adopters reported burning through $100+
per hour in API credits when running at full tilt.

I had been using Claude Code as Gas Town's primary agent, and the quality was
excellent. However, as I started scaling up to more concurrent agents and longer
sessions, the bill started to look less like a utility cost and more like a car
payment. Three things pushed me to explore a local inference setup:

1. **Cost**: Running a dozen agents in parallel for hours on end adds up
quickly, even with smaller models
2. **Control**: I wanted the ability to experiment with different models,
quantization levels, context window sizes, inference parameters and other
advanced optimization techniques without
being locked into a single provider
3. **Privacy**: Some of the projects I run through Gas Town may involve sensitive
data. Keeping inference entirely on my local network eliminates that
concern 

## The Hardware: NVIDIA DGX Spark

The [DGX Spark](https://www.nvidia.com/en-us/products/workstations/dgx-spark/){:target="_blank"}
is built around NVIDIA's GB10 Grace Blackwell Superchip. The specs that matter
most for local inference are:

- **128 GB unified LPDDR5x memory** shared between the CPU and GPU
- **Blackwell GPU** with 6,144 CUDA cores and fifth-generation Tensor Cores
supporting FP4
- **Up to 1 petaFLOP** of FP4 AI performance
- **ConnectX-7 Smart NIC** with two QSFP connectors (up to 200 Gbps), which
means you can link two Sparks together if you outgrow a single unit

The 128 GB of unified memory is the real selling point here.
Qwen3-Coder-Next-FP8 is an 80B parameter MoE (mixture-of-experts) model with
only 3B active parameters at inference time, and the FP8-quantized checkpoint
fits comfortably within roughly 46 GB. That leaves a healthy amount of headroom
for KV cache, vLLM overhead, and the operating system itself.

> The DGX Spark received a significant software update at CES 2026 that
> delivered up to 2.5x performance improvements through TensorRT-LLM
> optimizations and speculative decoding. Make sure your system is up to date
> before benchmarking.
{: .prompt-tip }

## The Model: Qwen3-Coder-Next-FP8

[Qwen3-Coder-Next](https://github.com/QwenLM/Qwen3-Coder){:target="_blank"}
is purpose-built for coding agents and local development. A few things make it
a particularly good fit for this use case:

- **3B active parameters** (80B total) thanks to the MoE architecture,
achieving performance comparable to models with 10 to 20x more active
parameters
- **256K context length**, which is critical for agentic workflows where
tool definitions, system prompts, and multi-turn conversations can eat through
context quickly
- **Strong tool calling support**, meaning it can handle the function calls that
OpenCode (and by extension, Gas Town) relies on
- **FP8 quantization** with a block size of 128, balancing quality and memory
efficiency

The FP8 variant is the sweet spot for the DGX Spark. It's small enough to run
comfortably with generous KV cache allocation, but large enough to produce
quality output for complex coding tasks.

> This model operates in non-thinking mode only. It does not generate
> `<think></think>` blocks. Keep this in mind if you're comparing output
> behavior with reasoning-enabled models.
{: .prompt-info }

## Setting Up the Inference Server with vLLM (Docker)

[vLLM](https://docs.vllm.ai/){:target="_blank"} is an inference engine that
maximizes throughput and minimizes memory waste using PagedAttention and
continuous batching. It exposes an OpenAI-compatible API, which is exactly what
OpenCode needs to connect. NVIDIA provides a pre-built vLLM Docker image
optimized for the DGX Spark's ARM64 Blackwell architecture, so we don't need
to build anything from source.

### Prerequisites

Ensure you have the following:

- DGX Spark with the latest system software
- Docker installed and configured with NVIDIA runtime
- Access to the [NVIDIA container registry](https://build.nvidia.com/spark/vllm){:target="_blank"}
(`nvcr.io`)

### Serving the Model

NVIDIA publishes optimized vLLM images to their container registry. We can pull
the image and serve the model in a single command:

```bash
docker run -it \
    --gpus all \
    -p 8000:8000 \
    -v /home/dominic/dgx-spark/cache/huggingface:/root/.cache/huggingface \
    nvcr.io/nvidia/vllm:26.02-py3 \
    vllm serve Qwen/Qwen3-Coder-Next-FP8 \
        --served-model-name qwen3-coder-next \
        --enable-auto-tool-choice \
        --tool-call-parser qwen3_coder \
        --gpu-memory-utilization 0.85 \
        --enable-prefix-caching \
        --attention-backend flashinfer
```

A few notes on the flags:

- `--gpus all` and `-p 8000:8000`: Gives the container full GPU access and
exposes the inference API on port 8000
- `--served-model-name qwen3-coder-next`: Aliases the model with a shorter
name, which simplifies the OpenCode and Gas Town configuration downstream
- `--enable-auto-tool-choice` and `--tool-call-parser qwen3_coder`: Required
for OpenCode's tool calling to work properly
- `--gpu-memory-utilization 0.85`: Allocates 85% of available GPU memory to
vLLM, leaving headroom for the OS and other processes. You can push this higher
if you're not running anything else on the Spark
- `--enable-prefix-caching`: Caches common prompt prefixes across requests,
which is a significant optimization when multiple Gas Town agents share similar
system prompts and tool definitions
- `--attention-backend flashinfer`: Uses the
[FlashInfer](https://github.com/flashinfer-ai/flashinfer){:target="_blank"}
attention backend for improved throughput on Blackwell GPUs

> If the container exits with an out-of-memory error, try lowering
> `--gpu-memory-utilization` (e.g., 0.75) or adding `--max-model-len 32768` to
> cap the context window. Check the logs with `docker logs <container_id>`.
{: .prompt-warning }

The first run will pull the model weights from Hugging Face, which takes some
time depending on your connection. Subsequent starts are much faster thanks to
the mounted cache volume.

Once the server is ready, verify it's healthy:

```bash
curl http://192.168.2.96:8000/v1/models
```

```json
{
    "object": "list",
    "data": [
        {
            "id": "qwen3-coder-next",
            "object": "model",
            "owned_by": "vllm"
        }
    ]
}
```

> Note the model ID in the response reflects the `--served-model-name` value,
> not the Hugging Face repository name. This is the ID you'll reference in your
> OpenCode and Gas Town configurations.
{: .prompt-info }

## Configuring OpenCode

[OpenCode](https://opencode.ai/){:target="_blank"} is a Go-based AI coding
agent built for the terminal. Unlike editor-embedded assistants, it lives in
your shell and works with any language, any editor, and any environment. More
importantly, it supports any OpenAI-compatible API endpoint, which means
pointing it at our local vLLM server is straightforward.

### Installation

```bash
curl -fsSL https://opencode.ai/install | bash
```

### Configuration

Create or edit `~/.config/opencode/opencode.json`:

```json
{
    "$schema": "https://opencode.ai/config.json",
    "provider": {
        "vllm": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "vLLM (local - DGX)",
            "options": {
                "baseURL": "http://192.168.2.96:8000/v1"
            },
            "models": {
                "qwen3-coder-next": {
                    "name": "qwen3-coder-next"
                }
            }
        },
        "vllm_small": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "vLLM (local - DGX - small)",
            "options": {
                "baseURL": "http://192.168.2.96:8001/v1"
            },
            "models": {
                "qwen2.5-3b-instruct": {
                    "name": "qwen2.5-3b-instruct"
                }
            }
        }
    },
    "model": "vllm/qwen3-coder-next",
    "small_model": "vllm_small/qwen2.5-3b-instruct"
}
```

There are a few things worth calling out here:

- **Two providers, two models**: I'm running two separate vLLM instances on
the Spark. The primary provider (`vllm`) serves Qwen3-Coder-Next on port 8000
for heavy lifting. The secondary provider (`vllm_small`) serves
Qwen2.5-3B-Instruct on port 8001 for lightweight tasks. This maps directly to
OpenCode's `model` and `small_model` fields, which control how it routes
requests internally
- **`baseURL` points to the Spark's LAN IP** (`192.168.2.96`), not
`localhost`. The DGX Spark sits on my local network as a dedicated inference
server, while OpenCode and Gas Town run on my primary workstation. If you're
running everything on the same machine, swap this to `http://localhost`
- The model names (`qwen3-coder-next`, `qwen2.5-3b-instruct`) must match the
`--served-model-name` values passed to vLLM when starting each container

Fire up OpenCode and confirm it connects:

```bash
opencode
```

If tool calls aren't working, the most common culprit is insufficient context
length. OpenCode's system prompt and tool definitions alone consume a
significant number of tokens. Qwen2.5-3B-Instruct is particularly sensitive to
this, so make sure the small model's vLLM instance has an adequate
`--max-model-len` configured.

## Wiring It Into Gas Town

With OpenCode successfully talking to our local models, the final step is
configuring Gas Town's `town-settings.json` to use OpenCode as the agent for
its various roles. Gas Town allows you to define custom agents and assign them
to specific roles, giving you granular control over which model handles what.

```json
{
    "type": "town-settings",
    "version": 1,
    "default_agent": "claude",
    "role_agents": {
        "polecat": "opencode-qwen3",
        "witness": "opencode-qwen3",
        "refinery": "opencode-qwen3",
        "deacon": "opencode-qwen3"
    },
    "agents": {
        "opencode-qwen2.5": {
            "command": "opencode",
            "args": [
                "--model", "vllm_small/qwen2.5-3b-instruct"
            ]
        },
        "opencode-qwen3": {
            "command": "opencode",
            "args": [
                "--model", "vllm/qwen3-coder-next"
            ]
        }
    }
}
```

A few things to note about this configuration:

- **`default_agent` remains `claude`**: The Mayor still runs on Claude for now.
As the primary orchestrator, the Mayor's decision quality has a cascading
effect on every downstream task. I'm not ready to hand that off to a local
model yet
- **All worker roles use `opencode-qwen3`**: Polecats (the ephemeral workers
that write code), the Witness (health monitor), the Refinery (merge queue), and
the Deacon (patrol loops) all run against Qwen3-Coder-Next via the local vLLM
instance. These roles account for the vast majority of token usage
- **`opencode-qwen2.5` is defined but not yet assigned**: I have the smaller
Qwen2.5-3B-Instruct agent ready as an option for lighter-weight roles. The
plan is to eventually route the Witness and Deacon to this model, as their
tasks are less demanding than actual code generation

At this point, Gas Town's Mayor dispatches tasks to Polecats running OpenCode
against the local model. The entire inference pipeline for worker agents stays
on the DGX Spark, and the only cloud API traffic comes from the Mayor itself.

## Early Observations

I've been running this setup for a few days now, and a few things stand out:

**Token throughput is the bottleneck, not quality.** Qwen3-Coder-Next-FP8
handles the vast majority of Gas Town's tasks competently. Where I notice a
difference compared to Claude is in throughput. When all Polecats are active
simultaneously, the single GPU has to serve requests sequentially (or with
limited batching), which introduces latency. For tasks that aren't
time-sensitive, this is perfectly acceptable. For rapid iteration loops, it can
feel slower.

**Cost savings are immediate and dramatic.** My previous Claude Code usage for
Gas Town was running north of $40 per day during active development sessions.
That's now zero on the inference side. The DGX Spark pays for itself within a
few months at that rate.

**The optimization surface is wide open.** This is what excites me most. With
full control over the inference stack, I can experiment with:

- Speculative decoding to improve throughput
- Different quantization levels (FP4 could free up even more memory for larger
context windows)
- Request batching and scheduling optimizations in vLLM
- Swapping in newer or more specialized models as they're released
- Linking a second DGX Spark for tensor parallel inference

None of this is possible when you're locked into a hosted API.

## What's Next

This setup is a starting point, not the endgame. I'm planning to explore
a few areas in the coming weeks:

- **Benchmarking**: Systematically comparing task completion quality and speed
between the local setup and Claude Code across different Gas Town workloads
- **Hybrid routing**: Using the local model for routine tasks (linting, simple
refactors, boilerplate generation) while routing complex architectural work to
a cloud API
- **Multi-model routing**: The `opencode-qwen2.5` agent is already configured
and ready to go. The next step is assigning it to the Witness and Deacon roles
to free up Qwen3-Coder-Next capacity for the Polecats

If you're running Gas Town and the API bill is giving you pause, I'd encourage
you to look into a local inference setup. The DGX Spark is not the only option
here; any machine with sufficient GPU memory can serve as the foundation. The
important part is that the entire stack, from vLLM to OpenCode to Gas Town, is
built around OpenAI-compatible APIs, making the components interchangeable.

As always, feel free to reach out via [Twitter](https://twitter.com/0xdeadbeefJERKY){:target="_blank"} with any questions/comments.

Happy (hacking\|hunting)!
