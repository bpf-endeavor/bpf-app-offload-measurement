# What is it?

I am trying to characterize the benefits of BPF-offload in respect to running a
program in userspace. This way, we could have a metric for deciding how
offloading reduces the performance overheads.


# Methodology

	[DUT] <--> [Load Gen]

Load generator sends traffic toward a server machine. The server runs the same
program in uesrspace (original case) and in one of the BPF hooks (e.g., XDP).
The throughput of the responses are captured for each case. The benfit factor
of offloading is declared as ratio of BPF throughput to the original case
throughput. This experiment is performed under different sizes for the request
and response.


# How these data helps use decide what to offload

## Benefits of Context Switch (Receive and Send)
When going from BPF to User space, the system will lose some benefits. The
benefit-loss value is obtained form the experiment with the same BPF-Hook and
request size.

Similarly, when a response is sent from user space the benefit of responding
from the kernel is lost. This benefit is looked up based on the BPF-Hook and
the size of the response size being sent.

If a size is not available in our experiments, closest value present is used.

## Benefit of Data-Summarization

When we are going from BPF to user space, we will lose some benefit.
The benefit lost could lookuped from a table as describe in previous part
(receive side). When we summarize data, we send smaller requests to user.
So the benefit lost for the original program and offload program would be
looked up from different cells of the table. We hope by reducing the data size
we lose smaller amount of benefit than the original case.


# Running

This requires Kashk to be installed. Use make (look at the available targets).

**Funny Note:**
I am trying to generate the benchmark for both XDP and SK\_SKB from a single
userspace program. let's see if the tool we are developing can help.
