<h1 align="center">🦅 Hawk-eye </h1> 
<p align="center"><b>Find PII & Secrets like never before across your entire infrastructure with same tool!</b></p>
<p align="center">
<a href="#description">Description</a> • <a href="#installation">Installation</a> • <a href="#features">Features</a> • <a href="#config">Configuration</a> • <a href="#acknowledgements">Acknowledgements</a><br><br>

<img alt="Static Badge" src="https://img.shields.io/badge/Supports-S3-yellow?logo=amazons3">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-GCP-red?logo=googlecloud">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-MysQL-green?logo=mysql">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-PostgreSQL-blue?logo=postgresql">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-Redis-red?logo=redis">
<img alt="Static Badge" src="https://img.shields.io/badge/Supports-On Prem-black?logo=amazonec2">
</p>

<div id="description">

### 🦅 Hawk Eye - Uncover Secrets and PII Across All Platforms in Minutes!

Hawk Eye is a robust, command-line tool built to safeguard against data breaches and cyber threats. Much like the sharp vision of a hawk, it quickly scans multiple data sources—S3, MySQL, PostgreSQL, MongoDB, CouchDB, Google Drive, Slack, Redis, Firebase, file systems, and Google Cloud buckets (GCS)—for Personally Identifiable Information (PII) and secrets. Using advanced text analysis and OCR techniques, HAWK Eye delves into various document formats like docx, xlsx, pptx, pdf, images (jpg, png, gif), compressed files (zip, tar, rar), and even video files to ensure comprehensive protection across platforms.


### Why "HAWK Eye"?
Like the keen vision of a hawk, this tool enables you to monitor and safeguard your data with precision and accuracy, ensuring data privacy and security.
</div>

## Commercial Support

For commercial support and help with HAWK Eye, please contact us on [LinkedIn](https://linkedin.com/in/rohitcoder) or [Twitter](https://twitter.com/rohitcoder).

Alternatively, you can reach out to us in our Slack community.

## HAWK Eye in Action

See how this works on Youtube - https://youtu.be/LuPXE7UJKOY

![HAWK Eye Demo](assets/preview.png)
![HAWK Eye Demo](assets/preview2.png)


<div id="installation">

## Installation via pip or pip3
   ```bash
      pip3 install hawk-scanner
   ```

## How to use hawk-eye?
### Using Docker hub (Fastest & Easiest approach)
```
docker run --rm \
  --platform linux/amd64 \
  -v /Users/kumarohit/Desktop/Projects/hawk-eye/connection.yml:/app/connection.yml \
  -v /Users/kumarohit/Desktop/Projects/hawk-eye/fingerprint.yml:/app/fingerprint.yml \
  rohitcoder/hawk-eye \
  slack --connection /app/connection.yml --fingerprint /app/fingerprint.yml
```
Just mount connection.yml and fingerprint.yml file in the container and run the command you want to run.

### Using hawk-eye binaries
1. Example working command (Use all/fs/s3/gcs etc...)
   ```bash
      hawk_scanner all --connection connection.yml --fingerprint fingerprint.yml --json output.json --debug
   ```
2. Pass connection data as CLI input in --connection-json flag, and output in json data (Helpful for CI/CD pipeline or automation)
   ```bash
     hawk_scanner fs --connection-json '{"sources": {"fs": {"fs1": {"quick_scan": true, "path": "/Users/rohitcoder/Downloads/data/KYC_PDF.pdf"}}}}' --stdout --quiet --fingerprint fingerprint.yml
   ```

3. You can also import Hawk-eye in your own python scripts and workflows, for better flexibility
   ```python
      from hawk_scanner.internals import system
      pii = system.scan_file("/Users/kumarohit/Downloads/Resume.pdf")
      print(pii)
   ```

4. You can also import Hawk-eye with custom fingerprints in your own python scripts like this
```python
   from hawk_scanner.internals import system
   pii = system.scan_file("/Users/kumarohit/Downloads/Resume.pdf", {
       "fingerprint": {
         "Email": '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}',
      }
   )
   print(pii)
   ```

## Platform and arch-specific guidelines

### Postgresql
You have to install some extra dependencies.
For scanning postgresql source, this tool requires ``psycopg2-binary`` dependency, we can't ship this dependency with main package because psycopg2-binary not works with most of the systems espically with Windows, so you have to install it manually.
   
   ```bash
      pip3 install psycopg2-binary
   ```

### Redhat Linux
You may get error after running ``hawk-scanner`` command on redhat from ``cv2`` dependency . You need to install some extra dependencies
```
yum install mesa-libGL
```

## Building or running from source

HAWK Eye is a Python-based CLI tool that can be installed using the following steps:

1. Clone the HAWK Eye repository to your local machine.
   ```bash
      git clone https://github.com/rohitcoder/hawk-eye.git
   ```
2. Navigate to the HAWK Eye directory.
3. Run the following command to install the required dependencies:
   ```bash
      pip3 install -r requirements.txt
   ```
4. Create a connection.yml file in the root directory and add your connection profiles (see the "How to Configure HAWK Eye Connections" section for details).
5. Run the following command to install HAWK Eye:
   ```bash
      python3 hawk_scanner/main.py
   ```
</div>

<div id="features">

## Key features
- Swiftly scans multiple data sources (S3, MySQL, PostgreSQL, Redis, Firebase, filesystem, and GCS) for PII data and malware exposure.
- Advanced algorithms and deep scanning capabilities provide thorough security auditing.
- Real-time alerts and notifications keep you informed of potential data vulnerabilities using Slack and other integrations, with more coming soon.
- New command support for S3, MySQL, PostgreSQL, Redis, Firebase, filesystem, and GCS expands the tool's capabilities.
- ``--debug`` flag enables printing of all debugging output for comprehensive troubleshooting.
- Save output in JSON format using the --json flag and specify a file name like --json output.json.
- Proudly crafted with love and a sense of humor to make your security journey enjoyable and stress-free.


## Usage
To unleash the power of HAWK Eye, simply follow the steps mentioned in the "Usage" section of the "README.md" file.

### Options
Note: If you don't provide any command, it will run all commands (firebase, fs, gcs, mysql, text, couchdb, gdrive, gdrive workspace, slack, postgresql, redis, s3) by default.
<table>
   <thead>
      <tr>
         <th>Option</th>
         <th>Description</th>
      </tr>
   </thead>
   <tbody>
      <tr>
         <td>
           firebase
         </td>
         <td>Scan Firebase profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            fs
            <commit_id>
         </td>
         <td>Scan filesystem profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            gcs
         </td>
         <td>Scan GCS (Google Cloud Storage) profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            text
         </td>
         <td>Scan text or string for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            mysql
         <td>Scan MySQL profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            mongodb
         <td>Scan MongoDB profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            couchdb
         <td>Scan CouchDB profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            slack
         <td>Scan slack profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            postgresql
         <td>Scan postgreSQL profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            redis
         </td>
         <td>Scan Redis profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            s3
          </td>
         <td>Scan S3 profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            gdrive
          </td>
         <td>Scan Google drive profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>
            gdrive_workspace
          </td>
         <td>Scan Google drive Workspace profiles for PII and secrets data.</td>
      </tr>
      <tr>
         <td>--connection</td>
         <td>Provide a connection YAML local file path like --connection connection.yml, this file will contain all creds and configs for different sources and other configurations.</td>
      </tr>
      <tr>
         <td>--connection-json</td>
         <td>Provide a connection json as CLI Input, helpful when you want to run this tool in CI/CD pipeline or automation.</td>
      </tr>
      <tr>
         <td>--fingerprint</td>
         <td>Provide a fingerprint file path like --fingerprint fingerprint.yml, this file will override default fingerprints.</td>
      </tr>
      <tr>
         <td>--debug</td>
         <td>Enable Debug mode.</td>
      </tr>
      <tr>
         <td>--stdout</td>
         <td>Print output on stdout or terminal.</td>
      </tr>
      <tr>
         <td>--quiet</td>
         <td>Use --quiet flag if you want to hide all logs from your terminal.</td>
      </tr>
      <tr>
         <td>--json</td>
         <td>Provide --json file name to save output in json file like --json output.json</td>
      </tr>
      <tr>
         <td>--shutup</td>
         <td>Use --shutup flag if you want to hide Hawk ASCII art from your terminal 😁</td>
      </tr>
   </tbody>
</table>
</div>

<div id="config">

## How to Configure HAWK Eye Connections (Profiles in connection.yml)

HAWK Eye uses a YAML file to store connection profiles for various data sources. The connection.yml file is located in the config directory. You can add new profiles to this file to enable HAWK Eye to scan additional data sources. The following sections describe the process for adding new profiles to the connection.yml file.


### Your connection file will look like this

For the full connection schema, have a look at [connection.yml.sample](connection.yml.sample).

```yaml
notify:
  redacted: True
  suppress_duplicates: True
  slack:
    webhook_url: https://hooks.slack.com/services/T0XXXXXXXXXXX/BXXXXXXXX/1CIyXXXXXXXXXXXXXXX

sources:
  redis:
    redis_example:
      host: YOUR_REDIS_HOST
      password: YOUR_REDIS_PASSWORD
  s3:
    s3_example:
      access_key: YOUR_S3_ACCESS_KEY
      secret_key: YOUR_S3_SECRET_KEY
      bucket_name: YOUR_S3_BUCKET_NAME
      cache: true
  gcs:
    gcs_example:
      credentials_file: /path/to/your/credential_file.json
      bucket_name: YOUR_GCS_BUCKET_NAME
      cache: true
      exclude_patterns:
        - .pdf
        - .docx
  firebase:
    firebase_example:
      credentials_file: /path/to/your/credential_file.json
      bucket_name: YOUR_FIREBASE_BUCKET_NAME
      cache: true
      exclude_patterns:
        - .pdf
        - .docx
  mysql:
    mysql_example:
      host: YOUR_MYSQL_HOST
      port: YOUR_MYSQL_PORT
      user: YOUR_MYSQL_USERNAME
      password: YOUR_MYSQL_PASSWORD
      database: YOUR_MYSQL_DATABASE_NAME
      limit_start: 0   # Specify the starting limit for the range
      limit_end: 500   # Specify the ending limit for the range
      tables:
        - table1
        - table2
      exclude_columns:
         - column1
         - column2
  postgresql:
    postgresql_example:
      host: YOUR_POSTGRESQL_HOST
      port: YOUR_POSTGRESQL_PORT
      user: YOUR_POSTGRESQL_USERNAME
      password: YOUR_POSTGRESQL_PASSWORD
      database: YOUR_POSTGRESQL_DATABASE_NAME
      limit_start: 0   # Specify the starting limit for the range
      limit_end: 500   # Specify the ending limit for the range
      tables:
        - table1
        - table2
  mongodb:
    mongodb_example:
      uri: YOUR_MONGODB_URI
      host: YOUR_MONGODB_HOST
      port: YOUR_MONGODB_PORT
      username: YOUR_MONGODB_USERNAME
      password: YOUR_MONGODB_PASSWORD
      database: YOUR_MONGODB_DATABASE_NAME
      uri: YOUR_MONGODB_URI  # Use either URI or individual connection parameters
      limit_start: 0   # Specify the starting limit for the range
      limit_end: 500   # Specify the ending limit for the range
      collections:
        - collection1
        - collection2
  fs:
    fs_example:
      path: /path/to/your/filesystem/directory
      exclude_patterns:
        - .pdf
        - .docx
        - private
        - venv
        - node_modules
  
 gdrive:
    drive_example:
      folder_name:
      credentials_file: /Users/kumarohit/Downloads/client_secret.json ## this will be oauth app json file
      cache: true
      exclude_patterns:
        - .pdf
        - .docx

  gdrive_workspace:
    drive_example:
      folder_name:
      credentials_file: /Users/kumarohit/Downloads/client_secret.json ## this will be service account json file
      impersonate_users:
        - usera@amce.org
        - userb@amce.org
      cache: true
      exclude_patterns:
        - .pdf
        - .docx
  text:
    profile1:
      text: "Hello World HHXXXXX"
  slack:
    slack_example:
      channel_types: "public_channel,private_channel"
      token: xoxp-XXXXXXXXXXXXXXXXXXXXXXXXX
      archived_channels: True ## By default False, set to True if you want to scan archived channels also
      limit_mins: 15 ## By default 60 mins
      limit_from: last_message ## By default current Unix timestamp, available options - UNIX Timestamp (e..g: 1737354387 last_message
      channel_ids:
      - XXXXXXXX
```

You can add or remove profiles from the connection.yml file as needed. You can also configure only one or two data sources if you don't need to scan all of them.
</div>

## Adding New Commands
HAWK Eye's extensibility empowers developers to contribute new security commands. Here's how:

1. Fork the HAWK Eye repository to your GitHub account.
2. Create a new Python file for your security command inside the commands directory, with a descriptive name.
3. Define a function execute(args) within the new Python file, containing the logic for your command.
4. Provide clear documentation and comments explaining the purpose and usage of the new command.
5. Thoroughly test your command to ensure it works seamlessly and aligns with the existing features.
6. Submit a pull request from your branch to the main HAWK Eye repository.
7. The maintainers will review your contribution, provide feedback if needed, and merge your changes.

## Contribution Guidelines
We welcome contributions from the open-source community to enhance HAWK Eye's capabilities in securing data sources. To contribute:

1. Fork the HAWK Eye repository to your GitHub account.
2. Create a new branch from the main branch for your changes.
3. Adhere to the project's coding standards and style guidelines.
4. Write clear and concise commit messages for your changes.
5. Include appropriate test cases for new features or modifications.
6. Update the "README.md" file to reflect any changes or new features.
7. Submit a pull request from your branch to the main branch of the HAWK Eye repository.
8. The maintainers will review your pull request and work with you to address any concerns.
9. After approval, your contributions will be merged into the main codebase.

Join the HAWK Eye community and contribute to data source security worldwide. For any questions or assistance, feel free to open an issue on the repository.

If you find HAWK Eye useful and would like to support the project, please consider making a donation. All 100% of the donations will be distributed to charities focused on education welfare and animal help.

<div id="acknowledgements">

## Conferences and Talks
<ul type="disc">
<li><a href="https://www.blackhat.com/sector/2023/arsenal/schedule/index.html#hawk-eye---pii--secret-detection-tool-for-your-servers-database-filesystems-cloud-storage-services-35716" target="_blank">
Black Hat SecTor 2023 [Arsenal]</a></li>
<li><a href="https://blackhatmea.com/session/hawk-eye-pii-secret-detection-tool-your-servers-database-filesystems-cloud-storage-0" target="_blank">
Black Hat Middle East and Africa 2023 [Arsenal]</a></li>
<li><a href="https://www.blackhat.com/eu-23/arsenal/schedule/index.html#hawk-eye---pii--secret-detection-tool-for-your-servers-database-filesystems-cloud-storage-services-35711" target="_blank">
Black Hat Europe 2023 [Arsenal]</a></li>
</ul>

[![Star History Chart](https://api.star-history.com/svg?repos=rohitcoder/hawk-eye&type=Date)](https://star-history.com/#rohitcoder/hawk-eye&Date)

## 💪 Contributors
We extend our heartfelt appreciation to all contributors who continuously improve this tool! Your efforts are essential in strengthening the security landscape. 🙏

<a href="https://github.com/rohitcoder/hawk-eye/graphs/contributors">
  <img src="https://contrib.rocks/image?abc=1&repo=rohitcoder/hawk-eye" />
</a>
</div>

## Donation
#### How to Donate
Feel free to make a donation directly to the charities of your choice or send it to us, and we'll ensure it reaches the deserving causes. Just reach out to us on [LinkedIn](https://linkedin.com/in/rohitcoder) or [Twitter](https://twitter.com/rohitcoder) to let us know about your contribution. Your generosity and support mean the world to us, and we can't wait to express our heartfelt gratitude.

Your donations will play a significant role in making a positive impact in the lives of those in need. Thank you for considering supporting our cause!
