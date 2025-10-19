# Simple PHP Wiki

**vibe-coded, so use at your own risk! Code was double checked by several models including GPt-5 and Claude 4.5**

A lightweight, secure, and easy-to-use flat-file wiki engine built with PHP. It uses Markdown for page content and requires no database, making it incredibly simple to set up and manage.

## Key Features

- **Flat-File CMS**: No database needed. All pages are stored as individual Markdown (`.md`) files.
- **Markdown Support**: Write and edit pages using standard Markdown syntax, powered by Parsedown.
- **Secure by Design**:
    - **Content Security Policy (CSP)**: Utilizes a strict, nonce-based CSP to prevent XSS attacks.
    - **CSRF Protection**: All forms are protected against Cross-Site Request Forgery.
    - **Secure Authentication**: Features password hashing, login rate-limiting, and hardened session management.
    - **Safe File Uploads**: Re-encodes uploaded images to strip metadata and prevent attacks.
    - **Directory Traversal Protection**: Ensures users cannot access files outside of the designated content directory.
- **User Management**: Simple JSON-based user store for authentication.
- **Page and Content Features**:
    - Automatic backlinking and related page suggestions based on tags.
    - Full-text search across all pages.
    - Support for image uploads and embedding.
- **Minimal Dependencies**: Runs on standard PHP with no complex frameworks.

## Installation

1.  **Download Files**:
    Clone this repository or download the source code to your web server.
    ```
    git clone https://github.com/your-username/your-repo-name.git
    cd your-repo-name
    ```

2.  **Set Up Dependencies**:
    Download the `Parsedown.php` library and place it in the project's root directory.
    ```
    # You can get it from https://github.com/erusev/parsedown
    wget https://raw.githubusercontent.com/erusev/parsedown/master/Parsedown.php
    ```

3.  **Configure the Wiki**:
    Customize the settings in `config.php` 
   

4.  **Set Permissions**:
    Ensure your web server has write permissions for the directories defined in `config.php` (`pages`, `uploads`, `sessions`) and for the `users.json` and `rate_limits.json` files.
    ```
    # Example for a typical Linux server (adjust user/group as needed)
    chown -R www-data:www-data pages uploads sessions
    chmod -R 755 pages uploads sessions
    touch users.json rate_limits.json wiki.log
    chown www-data:www-data users.json rate_limits.json wiki.log
    chmod 640 users.json rate_limits.json wiki.log
    ```
    **Security Note**: For enhanced security, it is highly recommended to place data directories (`pages`, `uploads`, `sessions`, etc.) outside of the web root if your hosting environment allows it.

5.  **Create Your First User**:
    You need to manually create the first user account. Create a `users.json` file in your project root with the following structure:
    ```
    {
        "your_username": "your_hashed_password"
    }
    ```
    To generate a secure password hash, create a temporary PHP file (e.g., `hash_password.php`) with the following content, run it, and then delete the file:
    ```
    <?php
    echo password_hash('your_secret_password', PASSWORD_DEFAULT);
    ?>
    ```
    Execute it from the command line: `php hash_password.php`. Copy the resulting hash into your `users.json` file.

## Configuration

All configuration is handled in the `config.php` file. This file returns an array of settings:

-   `pages_dir`, `uploads_dir`, `sessions_dir`: Paths to data directories.
-   `users_file`, `rate_limit_file`, `log_file`: Paths to data and log files.
-   `default_page`: The name of the wiki's homepage (e.g., 'Home').
-   `session_lifetime`, `session_timeout`: Session duration and inactivity timeout settings.
-   `max_login_attempts`, `login_block_duration`: Brute-force protection settings.
-   `max_upload_size`, `max_content_size`: Limits for file uploads and page content.

## Usage

-   **Creating Pages**: To create a new page, simply create a link to it from an existing page using the format `[[Page Title]]`. When you click the link, you will be taken to the editor to create the new page.
-   **Editing Pages**: Click the "Edit this page" link at the bottom of any page to open the editor.
-   **Tags**: Add tags to your content by using hashtags (e.g., `#php`, `#security`). These automatically generate tag pages.
-   **Images**: Upload images using the editor toolbar and embed them using standard Markdown syntax. You can add alignment and sizing classes like this: `![alt text](image.jpg " .center .small ")`.

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/your-username/your-repo-name/issues).

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
