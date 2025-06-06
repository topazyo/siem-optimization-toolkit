# SIEM Optimization Toolkit

A comprehensive toolkit for optimizing Microsoft Sentinel SIEM implementation, focusing on cost management, performance optimization, and security enhancement.

## 🎯 Features

- Advanced log ingestion monitoring
- Cost optimization frameworks
- Custom KQL query templates
- Automated policy management
- Compliance-aware retention policies

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/yourusername/siem-optimization-toolkit

# Install dependencies
pip install -r requirements.txt

# Run initial setup
./scripts/setup/initialize.sh # This script also creates default configuration files and necessary directories if they are missing.
```

## 📊 Core Components

- **Ingestion Monitoring**: Real-time tracking of log volumes
- **Cost Analysis**: Automated cost tracking and optimization
- **Query Optimization**: Performance-tuned KQL queries; offers suggestions and can automatically apply or suggest common pattern-based optimizations.
- **Policy Automation**: Intelligent policy management

##  Azure Connectivity & Prerequisites

Certain tools within this toolkit, particularly those involving query benchmarking and direct interaction with your Log Analytics workspace (e.g., `AdvancedKQLOptimizer`, `QueryBenchmark`), require live connectivity to Azure. To use these features, please ensure the following prerequisites are met:

*   **Azure Subscription:** You must have an active Azure subscription.
*   **Log Analytics Workspace:** You need a Log Analytics workspace, and its Workspace ID must be provided to the relevant tools.
*   **Permissions:** The identity (user, service principal, or managed identity) executing the scripts needs appropriate read permissions on the Log Analytics workspace (e.g., "Log Analytics Reader" role or more specific data querying permissions like `Microsoft.OperationalInsights/workspaces/query/read`).
*   **Authentication:** The scripts leverage `DefaultAzureCredential` from the `azure-identity` Python library. This supports various authentication methods:
    *   **Azure CLI Login:** For local development, you can authenticate by running `az login` in your terminal.
    *   **Service Principal:** Set the following environment variables: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`.
    *   **Managed Identity:** If running in an Azure environment that supports Managed Identities (e.g., Azure VMs, App Service), configure the identity with the necessary permissions.
    *   Other methods supported by `DefaultAzureCredential` (see Azure SDK documentation for details).
*   **Costs and API Limits:** Be aware that querying Azure Log Analytics can incur costs based on the amount of data processed. Frequent or extensive benchmarking might also be subject to API rate limits or throttling by the Azure service. Monitor your usage accordingly.

## 📘 Documentation

Visit our [documentation](./docs/README.md) for detailed implementation guides.

## 🛠️ Examples

For detailed usage examples of various toolkit components, please see the [EXAMPLES.md](EXAMPLES.md) file.

## 🤝 Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.