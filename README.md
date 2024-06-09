# Security Protocol Based on Kerberos Security Protocol

This project implements a security protocol leveraging the Kerberos Security Protocol to ensure robust authentication and authorization mechanisms. By utilizing Single Sign-On (SSO) capabilities, users can access multiple services with a single set of credentials, streamlining the authentication process and enhancing user convenience. The Ticket Granting Service (TGS) plays a pivotal role in this architecture, issuing tickets that allow secure and verified access to various network resources. Adhering to secured programming principles, this protocol ensures that all communications and data exchanges are encrypted and safeguarded against common security threats, providing a fortified and reliable security solution.

## Features

- **Single Sign-On (SSO)**: Simplifies user authentication across multiple services with a single set of credentials.
- **Ticket Granting Service (TGS)**: Issues tickets for secure access to network resources.
- **Secure Communication**: Ensures all data exchanges are encrypted and protected against security threats.
- **Adherence to Secured Programming Principles**: Implements best practices in secure coding to safeguard against vulnerabilities.

## Code Files Description

- **AuthenticationServer.py**: Implements the authentication server that handles user login requests and issues Ticket Granting Tickets (TGTs).
- **MessageServer.py**: Manages the communication between clients and servers, ensuring secure message exchanges using Kerberos tickets.
- **Client.py**: Contains the client-side implementation for requesting authentication and accessing protected resources.
- **Utilization.py**: Provides utility functions to support various operations within the protocol.
- **Request.py**: Defines the structure and handling of request messages sent by the client to the server.
- **Response.py**: Defines the structure and handling of response messages sent by the server to the client.
- **UtilizationRequestResponse.py**: Manages the interactions and data exchanges related to utilization requests and responses.
- **RequestResponseValidity.py**: Validates the integrity and authenticity of requests and responses within the protocol.
- **fileValidity.py**: Ensures the validity and security of file-related operations and exchanges.
- **validators.py**: Contains a set of validation functions to verify inputs and ensure compliance with security standards.
- **Constants.py**: Defines constant values used throughout the project to maintain consistency and ease of configuration.
