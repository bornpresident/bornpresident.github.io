---
title: Guardrail Comparison
author: Vishal Chand
date: 2025-01-17
categories:
  - Artificial Intelligence
tags:
  - LLM Security
  - Guardrail
pin: false
math: true
mermaid: true
image:
  path: /assets/img/posts/1.png
---

What is Guardrail? Guardrails are used to identify the potential misuse in the query stage and to prevent the model from providing an answer that should not be given.

Why do we need our own guardrails? While global frameworks provide common principles, each country operates under its unique laws, regulations, and cultural sensitivities. For instance, an event like the Charlie Hebdo case in France, often defended under the principle of 'freedom of speech,' can deeply hurt religious sentiments. However, such instances would not align with the legal and cultural norms in India.

| Abilities           | Llama Guard | Nvidia NeMo | Guardrails AI | TruLens | Guidance AI | LMQL |
| ------------------- | ----------- | ----------- | ------------- | ------- | ----------- | ---- |
| Hallucination       | ✓           | ✓           | ✓             | ✓       | ✓           | ✓    |
| Fairness            | ✓           | -           | ✓             | ✓       | ✓           | -    |
| Privacy             | -           | ✓           | -             | -       | -           | -    |
| Robustness          | -           | -           | -             | -       | -           | -    |
| Toxicity            | ✓           | ✓           | ✓             | ✓       | ✓           | ✓    |
| Legality            | ✓           | -           | -             | -       | ✓           | -    |
| Out-of-Distribution | -           | -           | ✓             | -       | -           | -    |
| Uncertainty         | -           | ✓           | ✓             | ✓       | -           | -    |


> **Out-of-Distribution (OOD)** refers to data that does not belong to any class present in the training set of a deep neural network (DNN). OOD data differs from in-distribution data in certain dimensions, and DNNs often make overconfident predictions when exposed to it.
{: .prompt-info }

#### Llama Guard:
- Built by Meta on the Llama2-7b architecture for improving AI conversation safety
- Functions as a fine-tuned model that analyzes both input and output of the target model
- Makes classifications based on user-defined categories
- Offers flexibility through zero/few-shot learning to adapt to different guidelines and requirements
- Has limitations in reliability since results depend on:
	  -  The LLM's interpretation of categories
	  - The model's prediction accuracy
#### NVIDIA Nemo:
- Uses Colang (executable program language) for setting dialogue constraints
- Key Processing Steps:
  1. Embeds input prompts into vectors
  2. Uses KNN to compare with stored canonical forms
  3. Employs "sentence-transformers/all-MiniLM-L6-v2" model for embeddings
  4. Uses Annoy algorithm for efficient nearest-neighbor search
- LLM Integration in Three Phases:
  1. Generates user intent (using examples and top 5 potential intents)
  2. Generates next step (searches and integrates similar flows)
  3. Generates bot-message (uses examples and relevant context chunks)
- Additional Features:
  - Includes pre-implemented moderations for fact-checking
  - Handles hallucination prevention
  - Provides content moderation
- Classification: Type-1 neural-symbolic system, with effectiveness dependent on KNN performance.
[Paper Link](https://arxiv.org/pdf/2310.10501)
#### Guardrails AI:
- Adds structure, type, and quality guarantees to LLM outputs
- Three-Step Operation Process:
  1. Defines "RAIL" specifications in XML format for output limitations
  2. Initializes the "guard" with optional classifier models for specialized processing
  3. Wraps LLMs and triggers error correction when needed
- Error Handling:
  - Automatically generates corrective prompts
  - Makes LLMs regenerate answers
  - Re-checks output against specifications
- Limitations:
  - Only works with text-level checks
  - Cannot handle multimodal content (images/audio)
  - Classification: Type-2 neural-symbolic system, using symbolic algorithms supported by learning algorithms (classifier models)

#### TruLens:

-  An open-source toolkit for LLM development, evaluation, and monitoring
- Core Features:
	  - TruLens-Eval for quality assurance against predefined standards
	  - Logging capability for inputs and outputs
	  - Integration with various LLM providers
- Implementation Tools:
	1. Uses OpenAI API for groundedness assessment
	2. Employs NLI models with Hugging Face
	3. Incorporates embedding models for text-to-vector conversion
- Customization Options:
1. Allows custom feedback functions via Python
2. Enables tailored evaluations for specific requirements
- Monitoring Features:
 1. Performance metrics visualization through leaderboards
  2. Supports iterative model refinement
  3. Provides continuous evaluation framework








