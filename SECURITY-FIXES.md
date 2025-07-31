# Security Fixes for SSRF Vulnerabilities

This document outlines the SSRF (Server-Side Request Forgery) security vulnerabilities that were found and fixed in the WordPress Auto Upload Images plugin.

## Vulnerabilities Identified

### 1. Insufficient URL Validation (Critical)

-   **Location**: `src/ImageUploader.php` - `validate()` method
-   **Risk**: High
-   **Description**: The original validation only checked if the URL host was different from the site's host and if it was in an exclude list. This allowed attackers to:

-   Access internal services (127.0.0.1, 192.168.x.x, 10.x.x.x)
-   Query cloud metadata endpoints (169.254.169.254)
-   Use non-HTTP protocols (file://, ftp://, gopher://)

### 2. Unrestricted Protocol Support (High)

-   **Location**: `src/ImageUploader.php` - `downloadImage()` method
-   **Risk**: High  
    **Description**: The plugin accepted any URL protocol, allowing attackers to use dangerous protocols like `file://`, `ftp://`, or `gopher://` for SSRF attacks.

### 3. Insufficient URL Normalization (Medium)

-   **Location**: `src/ImageUploader.php` - `normalizeUrl()` method
-   **Risk**: Medium
-   **Description**: The URL normalization was too simplistic and didn't validate the resulting URLs properly.

### 4. Missing Input Validation (Medium)

-   **Location**: `src/WpAutoUpload.php` - `findAllImageUrls()` method
-   **Risk**: Medium
-   **Description**: No validation of extracted URLs before processing them.

## Security Fixes Implemented

### 1. Enhanced URL Validation

-   Added comprehensive IP address validation using `filter_var()` with `FILTER_FLAG_NO_PRIV_RANGE` and `FILTER_FLAG_NO_RES_RANGE`
-   Explicit blocking of common internal IP ranges:
    -   127.0.0.0/8 (localhost)
    -   10.0.0.0/8 (private network)
    -   172.16.0.0/12 (private network)
    -   192.168.0.0/16 (private network)
    -   169.254.0.0/16 (link-local/AWS metadata)
-   DNS resolution validation for hostnames
-   Blocking of specific dangerous IPs like 169.254.169.254 (AWS metadata endpoint)

### 2. Protocol Restriction

-   Only HTTP and HTTPS protocols are now allowed
-   All other protocols (file://, ftp://, gopher://, etc.) are blocked
-   Protocol validation is enforced at multiple levels

### 3. Improved URL Normalization

-   Complete URL reconstruction to prevent injection attacks
-   Validation of URL structure before normalization
-   Safe handling of protocol-relative URLs

### 4. Input Validation

-   Added `isValidImageUrl()` method to validate URLs before processing
-   Length limits on URLs (max 2048 characters)
-   Character validation to prevent injection attacks
-   Better error handling for malformed URLs

### 5. HTTP Request Security

-   Added proper timeout settings (30 seconds)
-   Limited redirects (max 3)
-   SSL verification enabled
-   Proper User-Agent header
-   Additional security headers

### 6. Settings Validation

-   Validation of base URL settings
-   Validation of excluded URLs list
-   Post type existence validation
-   Additional error handling and user feedback

## New Security Methods Added

### `isUrlSafe($host)`

Validates if a hostname/IP is safe to connect to by checking against private IP ranges and known dangerous endpoints.

### `isIpSafe($ip)`

Validates specific IP addresses against private/reserved ranges and known metadata endpoints.

### `isValidImageUrl($url)`

Performs basic validation on extracted image URLs before processing.

### `isValidBaseUrl($url)`

Validates base URL settings in the admin panel.

### `validateExcludeUrls($urls_text)`

Validates the excluded URLs list in settings.

## Testing

A comprehensive test suite has been added in `tests/test-security-fixes.php` that validates:

-   Private IP blocking
-   Protocol validation
-   URL normalization security
-   Malformed URL rejection
-   Cloud metadata endpoint blocking

## Impact

These fixes prevent the following attack vectors:

-   ✅ Internal network scanning
-   ✅ Cloud metadata service access
-   ✅ Local file access via file:// protocol
-   ✅ Port scanning of internal services
-   ✅ Bypass attempts using IP addresses
-   ✅ Protocol-based attacks
-   ✅ URL injection attacks

## Backward Compatibility

All fixes maintain backward compatibility with legitimate use cases while blocking malicious requests. Users should not experience any functionality loss with these security improvements.
