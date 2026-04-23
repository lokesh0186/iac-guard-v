#!/usr/bin/env python3
"""
Bedrock API caller for IaC-Guard-V experiments.
Supports Claude (Anthropic) and Llama 4 (Meta) via inference profiles.
"""
import boto3
import json
import time

MODELS = {
    'claude-sonnet-4.6': {
        'model_id': 'us.anthropic.claude-sonnet-4-6',
        'family': 'anthropic',
    },
    'llama4-maverick': {
        'model_id': 'us.meta.llama4-maverick-17b-instruct-v1:0',
        'family': 'meta',
    },
    'claude-opus-4.6': {
        'model_id': 'us.anthropic.claude-opus-4-6-v1',
        'family': 'anthropic',
    },
}

client = boto3.client('bedrock-runtime', region_name='us-east-1')


def call_model(model_name, prompt, max_tokens=4096):
    """Call a Bedrock model and return response text + metadata."""
    config = MODELS[model_name]
    start = time.time()

    if config['family'] == 'anthropic':
        body = json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': max_tokens,
            'messages': [{'role': 'user', 'content': prompt}],
            'temperature': 0.0,
        })
        response = client.invoke_model(
            modelId=config['model_id'],
            contentType='application/json',
            accept='application/json',
            body=body,
        )
        result = json.loads(response['body'].read())
        text = result['content'][0]['text']
        usage = result.get('usage', {})
        metadata = {
            'input_tokens': usage.get('input_tokens', 0),
            'output_tokens': usage.get('output_tokens', 0),
        }

    elif config['family'] == 'meta':
        formatted = (
            f'<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n'
            f'{prompt}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n'
        )
        body = json.dumps({
            'prompt': formatted,
            'max_gen_len': max_tokens,
            'temperature': 0.0,
        })
        response = client.invoke_model(
            modelId=config['model_id'],
            contentType='application/json',
            accept='application/json',
            body=body,
        )
        result = json.loads(response['body'].read())
        text = result.get('generation', '')
        metadata = {
            'input_tokens': result.get('prompt_token_count', 0),
            'output_tokens': result.get('generation_token_count', 0),
        }

    elapsed = time.time() - start
    metadata['latency_seconds'] = round(elapsed, 2)
    metadata['model_name'] = model_name
    metadata['model_id'] = config['model_id']

    return text, metadata


if __name__ == '__main__':
    # Quick test
    for model in ['claude-sonnet-4.6', 'llama4-maverick']:
        text, meta = call_model(model, 'Say hello in one word.')
        print(f'{model}: "{text.strip()}" | {meta}')
