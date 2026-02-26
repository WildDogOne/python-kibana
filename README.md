# Kibana Python Client

A Python client library for interacting with the Kibana API. This library provides a convenient way to manage Kibana resources such as data views, fleet packages, agent policies, detection rules, and exception lists.

## Features

- **Data Views**: Create, retrieve, and delete data views
- **Fleet Management**: Install, update, and manage Elastic packages
- **Agent Policies**: Create and manage agent policies
- **Detection Rules**: Manage detection rules and exception lists
- **Alerts**: Close and acknowledge alerts

## Installation

```bash
pip install kibana-python
```

## Usage

### Basic Setup

```python
from kibana.kibana import kibana

# Using API Key authentication
kibana_client = kibana(
    base_url="https://your-kibana-instance.com",
    api_key="your-api-key"
)

# Using username/password authentication
kibana_client = kibana(
    base_url="https://your-kibana-instance.com",
    username="your-username",
    password="your-password"
)
```

### Data Views

```python
# Create a data view
dataview_config = {
    "name": "logs-*",
    "timeFieldName": "@timestamp"
}
response = kibana_client.create_dataview(dataview_config)

# Get a data view by name
dataview_id = kibana_client.get_dataview("logs-*")

# Delete a data view
kibana_client.delete_dataview(dataview_id)
```

### Fleet Management

```python
# Install a package
kibana_client.install_package("apm")

# Check if a package is installed
is_installed = kibana_client.get_install_status("apm")

# Delete a package
kibana_client.delete_package("apm")

# Update a package
kibana_client.update_package("apm")
```

### Agent Policies

```python
# Create an agent policy
kibana_client.create_agent_policy("my-policy")

# Get an agent policy
policy = kibana_client.get_agent_policy("my-policy")

# Delete an agent policy
kibana_client.delete_agent_policy("my-policy")
```

### Package Policies

```python
# Create a package policy
kibana_client.create_package_policy(
    package_policy_name="apm-policy",
    package_name="apm",
    agent_policy="my-policy"
)
```

### Fleet Outputs

```python
# Create a fleet output
kibana_client.create_fleet_output(
    hosts=["https://elasticsearch:9200"],
    output_name="my-elasticsearch"
)

# Get all fleet outputs
outputs = kibana_client.get_fleet_outputs()

# Update a fleet output
kibana_client.update_fleet_output(
    output_name="my-elasticsearch",
    hosts=["https://new-elasticsearch:9200"]
)

# Delete a fleet output
kibana_client.delete_fleet_output("my-elasticsearch")
```

### Detection Rules

```python
# Get all rules
all_rules = kibana_client.get_all_rules()

# Get a specific rule
rule = kibana_client.get_rule("rule-id")

# Bulk change rules
kibana_client.bulk_change_rules(
    rule_ids=["rule-1", "rule-2"],
    action="enable"
)
```

### Exception Lists

```python
# Get all exception lists
exception_lists = kibana_client.get_all_exception_lists()

# Create an exception container
kibana_client.create_exception_container(
    container_name="my-exceptions",
    container_type="detection"
)

# Get an exception container
container = kibana_client.get_exception_container("my-exceptions")

# Delete an exception container
kibana_client.delete_exception_container("my-exceptions")

# Attach exception container to a rule
kibana_client.attach_container_to_rule(
    container_name="my-exceptions",
    rule_name="my-rule"
)
```

### Alerts

```python
# Close alerts
kibana_client.post_close_alert(["signal-1", "signal-2"])

# Acknowledge alerts
kibana_client.post_ack_alert(["signal-1", "signal-2"])
```

### Machine Learning Jobs

```python
# Enable prebuilt ML job
kibana_client.enable_prebuild_ml_job("anomaly-detection")

# Disable prebuilt ML job
kibana_client.disable_prebuild_ml_job("anomaly-detection")

# Load prebuilt rules
kibana_client.load_prebuilt_rules()

# Get prebuilt rules status
status = kibana_client.get_prebuilt_rules_status()
```

## Configuration

### SSL Verification

By default, SSL verification is enabled. To disable it:

```python
kibana_client = kibana(
    base_url="https://your-kibana-instance.com",
    api_key="your-api-key",
    ssl_verify=False
)
```

## Error Handling

The library uses Python's logging module for error handling. Make sure to configure logging in your application:

```python
import logging

logging.basicConfig(level=logging.INFO)
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License.

## Support

For issues and questions, please open an issue on the GitHub repository.
