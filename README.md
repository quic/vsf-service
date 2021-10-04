Copyright (c) 2020, Qualcomm Innovation Center, Inc. All rights reserved.  
SPDX-License-Identifier: BSD-3-Clause  

# VSF Service
A reference model to show case parsing, storing and reporting of CVE data from fossid scan run against software builds.

## Requirements
* Python 3.9+
* `pip`, `setuptools`

## Usage

### Bring up the service
```
docker-compose up --build
```

### Bring down the service
```
docker-compose down

# To bring down all containers
docker-compose down -v
```

## Development
See [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## License
VSF Service is licensed under the BSD 3-clause “New” or “Revised” License. See [LICENSE](LICENSE) for the full license text.
