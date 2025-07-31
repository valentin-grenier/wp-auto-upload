<?php

/**
 * @author Ali Irani <ali@irani.im>
 */
class ImageUploader
{
    public $post;
    public $url;
    public $alt;

    public function __construct($url, $alt, $post)
    {
        $this->post = $this->sanitizePostData($post);
        $this->url = $url;
        $this->alt = $alt;
    }

    /**
     * Sanitize post data to prevent injection
     * @param array $post
     * @return array
     */
    private function sanitizePostData($post)
    {
        if (!is_array($post)) {
            return ['ID' => 0, 'post_name' => '', 'post_date_gmt' => ''];
        }

        $sanitized = [];

        // Sanitize ID
        $sanitized['ID'] = isset($post['ID']) ? absint($post['ID']) : 0;

        // Sanitize post name
        $sanitized['post_name'] = isset($post['post_name']) ? sanitize_title($post['post_name']) : '';

        // Sanitize date fields
        $sanitized['post_date_gmt'] = isset($post['post_date_gmt']) ? sanitize_text_field($post['post_date_gmt']) : '';

        // Keep other fields but sanitize them
        foreach ($post as $key => $value) {
            if (!isset($sanitized[$key]) && is_string($value)) {
                $sanitized[$key] = sanitize_text_field($value);
            } elseif (!isset($sanitized[$key])) {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    /**
     * Return host of url
     * @param null|string $url
     * @param bool $scheme
     * @param bool $www
     * @return null|string
     */
    public static function getHostUrl($url = null, $scheme = false, $www = false)
    {
        $url = $url ?: WpAutoUpload::getOption('base_url');

        $urlParts = parse_url($url);

        if (array_key_exists('host', $urlParts) === false) {
            return null;
        }

        $host = array_key_exists('port', $urlParts) ? $urlParts['host'] . ":" . $urlParts['port'] : $urlParts['host'];
        if (!$www) {
            $withoutWww = preg_split('/^(www(2|3)?\.)/i', $host, -1, PREG_SPLIT_NO_EMPTY); // Delete www from host
            $host = is_array($withoutWww) && array_key_exists(0, $withoutWww) ? $withoutWww[0] : $host;
        }
        return $scheme && array_key_exists('scheme', $urlParts) ? $urlParts['scheme'] . '://' . $host : $host;
    }

    /**
     * Check url is allowed to upload or not
     * @return bool
     */
    public function validate()
    {
        // Parse and validate the URL
        $parsed_url = parse_url($this->url);

        if (!$parsed_url || !isset($parsed_url['scheme']) || !isset($parsed_url['host'])) {
            return false;
        }

        // Only allow HTTP and HTTPS protocols
        if (!in_array(strtolower($parsed_url['scheme']), ['http', 'https'], true)) {
            return false;
        }

        // Validate against SSRF attacks
        if (!$this->isUrlSafe($parsed_url['host'])) {
            return false;
        }

        $url = self::getHostUrl($this->url);
        $site_url = self::getHostUrl() === null ? self::getHostUrl(site_url('url')) : self::getHostUrl();

        if ($url === $site_url || !$url) {
            return false;
        }

        if ($urls = WpAutoUpload::getOption('exclude_urls')) {
            $exclude_urls = explode("\n", $urls);

            foreach ($exclude_urls as $exclude_url) {
                if ($url === self::getHostUrl(trim($exclude_url))) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Check if URL is safe from SSRF attacks
     * @param string $host
     * @return bool
     */
    private function isUrlSafe($host)
    {
        // Resolve DNS only once to prevent TOCTOU attacks
        $ips = $this->getAllHostIPs($host);

        if (empty($ips)) {
            return false;
        }

        // Check all resolved IPs
        foreach ($ips as $ip) {
            if (!$this->isIpSafe($ip)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get all IP addresses for a hostname
     * @param string $host
     * @return array
     */
    private function getAllHostIPs($host)
    {
        $ips = [];

        // If it's already an IP address, validate and return
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return [$host];
        }

        // Resolve IPv4 addresses
        $ipv4_records = dns_get_record($host, DNS_A);
        if (is_array($ipv4_records)) {
            foreach ($ipv4_records as $record) {
                if (isset($record['ip'])) {
                    $ips[] = $record['ip'];
                }
            }
        }

        // Resolve IPv6 addresses
        $ipv6_records = dns_get_record($host, DNS_AAAA);
        if (is_array($ipv6_records)) {
            foreach ($ipv6_records as $record) {
                if (isset($record['ipv6'])) {
                    $ips[] = $record['ipv6'];
                }
            }
        }

        // Fallback to gethostbyname for IPv4 if DNS records failed
        if (empty($ips)) {
            $ip = gethostbyname($host);
            if ($ip !== $host && filter_var($ip, FILTER_VALIDATE_IP)) {
                $ips[] = $ip;
            }
        }

        return array_unique($ips);
    }

    /**
     * Check if IP address is safe (not in private/reserved ranges)
     * @param string $ip
     * @return bool
     */
    private function isIpSafe($ip)
    {
        // Validate IP format first
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Block private IP ranges using PHP's built-in filter
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return false;
        }

        // Additional checks for IPv4 addresses
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->isIPv4Safe($ip);
        }

        // Additional checks for IPv6 addresses
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->isIPv6Safe($ip);
        }

        return false;
    }

    /**
     * Check IPv4 address safety
     * @param string $ip
     * @return bool
     */
    private function isIPv4Safe($ip)
    {
        // Additional blocked IPv4 ranges not covered by PHP filters
        $blocked_ips = [
            '0.0.0.0',          // any address
            '127.0.0.1',        // localhost
            '169.254.169.254',  // AWS metadata
        ];

        if (in_array($ip, $blocked_ips, true)) {
            return false;
        }

        // Check against specific ranges that should be blocked
        $ip_long = ip2long($ip);
        if ($ip_long !== false) {
            $dangerous_ranges = [
                ['0.0.0.0', '0.255.255.255'],        // 0.0.0.0/8 - "This host on this network"
                ['100.64.0.0', '100.127.255.255'],   // 100.64.0.0/10 - Carrier-grade NAT
                ['169.254.0.0', '169.254.255.255'],  // 169.254.0.0/16 - Link-local
                ['224.0.0.0', '255.255.255.255'],    // 224.0.0.0/4 - Multicast and reserved
            ];

            foreach ($dangerous_ranges as $range) {
                $start = ip2long($range[0]);
                $end = ip2long($range[1]);
                if ($start !== false && $end !== false && $ip_long >= $start && $ip_long <= $end) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Check IPv6 address safety
     * @param string $ip
     * @return bool
     */
    private function isIPv6Safe($ip)
    {
        // Normalize IPv6 address
        $ip = inet_pton($ip);
        if ($ip === false) {
            return false;
        }

        // Block dangerous IPv6 ranges
        $dangerous_prefixes = [
            '::1',              // localhost
            'fe80:',            // link-local
            'fc00:',            // unique local
            'fd00:',            // unique local
            'ff00:',            // multicast
        ];

        $ip_hex = bin2hex($ip);
        foreach ($dangerous_prefixes as $prefix) {
            if ($prefix === '::1') {
                // Special case for localhost
                if ($ip_hex === '00000000000000000000000000000001') {
                    return false;
                }
            } else {
                // Check prefix
                $prefix_hex = str_replace(':', '', $prefix);
                if (strpos($ip_hex, $prefix_hex) === 0) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Create a secure temporary file
     * @param string $content
     * @return string|WP_Error
     */
    private function createSecureTempFile($content)
    {
        // Use WordPress upload directory for temp files instead of system temp
        $upload_dir = wp_upload_dir();
        $temp_dir = $upload_dir['basedir'] . '/aui-temp';

        // Create temp directory if it doesn't exist
        if (!is_dir($temp_dir)) {
            if (!wp_mkdir_p($temp_dir)) {
                return new WP_Error('aui_temp_dir_failed', 'AUI: Could not create temp directory.');
            }
        }

        // Generate secure filename
        $temp_filename = uniqid('aui_', true) . '.tmp';
        $temp_path = $temp_dir . DIRECTORY_SEPARATOR . $temp_filename;

        // Ensure path doesn't contain traversal attempts
        $real_temp_dir = realpath($temp_dir);
        $real_temp_path = $real_temp_dir . DIRECTORY_SEPARATOR . basename($temp_filename);

        if (strpos($real_temp_path, $real_temp_dir) !== 0) {
            return new WP_Error('aui_path_traversal', 'AUI: Invalid file path.');
        }

        // Write content securely
        $bytes_written = file_put_contents($real_temp_path, $content, LOCK_EX);
        if ($bytes_written === false) {
            return new WP_Error('aui_temp_write_failed', 'AUI: Could not write temp file.');
        }

        return $real_temp_path;
    }

    /**
     * Validate file path to prevent directory traversal
     * @param string $file_path
     * @param string $base_path
     * @return bool
     */
    private function isSecureFilePath($file_path, $base_path)
    {
        // Get real paths to prevent traversal
        $real_base = realpath($base_path);
        $real_file = realpath(dirname($file_path)) . DIRECTORY_SEPARATOR . basename($file_path);

        if ($real_base === false) {
            return false;
        }

        // Ensure file path is within base directory
        return strpos($real_file, $real_base . DIRECTORY_SEPARATOR) === 0;
    }

    /**
     * Clean up temporary files older than 1 hour
     */
    public static function cleanupTempFiles()
    {
        $upload_dir = wp_upload_dir();
        $temp_dir = $upload_dir['basedir'] . '/aui-temp';

        if (!is_dir($temp_dir)) {
            return;
        }

        $files = glob($temp_dir . '/*.tmp');
        $now = time();

        foreach ($files as $file) {
            if (is_file($file) && $now - filemtime($file) > 3600) { // 1 hour
                unlink($file);
            }
        }
    }

    /**
     * Return custom image filename with user rules
     * @return string
     */
    protected function getFilename()
    {
        $filename = trim($this->resolvePattern(WpAutoUpload::getOption('image_name', '%filename%')));
        return sanitize_file_name($filename ?: uniqid('img_', false));
    }

    /**
     * Returns original image filename if valid
     * @return string|null
     */
    protected function getOriginalFilename()
    {
        $urlParts = pathinfo($this->url);

        if (!isset($urlParts['filename'])) {
            return null;
        }

        return sanitize_file_name($urlParts['filename']);
    }

    private $_uploadDir;

    /**
     * Return information of upload directory
     * fields: path, url, subdir, basedir, baseurl
     * @param $field
     * @return string|null
     */
    protected function getUploadDir($field)
    {
        if ($this->_uploadDir === null) {
            $this->_uploadDir = wp_upload_dir(date('Y/m', time()));
        }
        return is_array($this->_uploadDir) && array_key_exists($field, $this->_uploadDir) ? $this->_uploadDir[$field] : null;
    }

    /**
     * Return custom alt name with user rules
     * @return string Custom alt name
     */
    public function getAlt()
    {
        $alt = $this->resolvePattern(WpAutoUpload::getOption('alt_name'));

        // Sanitize alt attribute to prevent XSS
        return esc_attr($alt);
    }

    /**
     * Returns string patterned
     * @param $pattern
     * @return string
     */
    public function resolvePattern($pattern)
    {
        preg_match_all('/%[^%]*%/', $pattern, $rules);

        $patterns = array(
            '%filename%' => $this->getOriginalFilename(),
            '%image_alt%' => $this->alt,
            '%date%' => date('Y-m-j'), // deprecated
            '%today_date%' => date('Y-m-j'),
            '%year%' => date('Y'),
            '%month%' => date('m'),
            '%day%' => date('j'), // deprecated
            '%today_day%' => date('j'),
            '%post_date%' => date('Y-m-j', strtotime($this->post['post_date_gmt'])),
            '%post_year%' => date('Y', strtotime($this->post['post_date_gmt'])),
            '%post_month%' => date('m', strtotime($this->post['post_date_gmt'])),
            '%post_day%' => date('j', strtotime($this->post['post_date_gmt'])),
            '%url%' => self::getHostUrl(get_bloginfo('url')),
            '%random%' => uniqid('img_', false),
            '%timestamp%' => time(),
            '%post_id%' => $this->post['ID'],
            '%postname%' => $this->post['post_name'],
        );

        if ($rules[0]) {
            foreach ($rules[0] as $rule) {
                // Escape the rule to prevent regex injection
                $escaped_rule = preg_quote($rule, '/');
                $replacement = array_key_exists($rule, $patterns) ? $patterns[$rule] : $rule;

                // Sanitize replacement value to prevent injection
                $safe_replacement = $this->sanitizePatternReplacement($replacement);

                $pattern = preg_replace("/$escaped_rule/", $safe_replacement, $pattern);
            }
        }

        return $pattern;
    }

    /**
     * Sanitize pattern replacement values
     * @param mixed $value
     * @return string
     */
    private function sanitizePatternReplacement($value)
    {
        if ($value === null) {
            return '';
        }

        // Convert to string and sanitize
        $value = (string) $value;

        // Remove potentially dangerous characters
        $value = preg_replace('/[<>"\'\\\]/', '', $value);

        // Limit length to prevent extremely long filenames
        return substr($value, 0, 100);
    }

    /**
     * Save image and validate
     * @return null|array image data
     */
    public function save()
    {
        // Normalize the URL first
        $normalized_url = self::normalizeUrl($this->url);
        if ($normalized_url === false) {
            return null;
        }
        $this->url = $normalized_url;

        if (!$this->validate()) {
            return null;
        }

        $image = $this->downloadImage($this->url);

        if (is_wp_error($image)) {
            return null;
        }

        return $image;
    }

    /**
     * Download image
     * @param $url
     * @return array|WP_Error
     */
    public function downloadImage($url)
    {
        $url = self::normalizeUrl($url);

        // Additional validation before making the request
        $parsed_url = parse_url($url);
        if (!$parsed_url || !isset($parsed_url['host'])) {
            return new WP_Error('aui_invalid_url', 'AUI: Invalid URL provided.');
        }

        // Final SSRF check before making request
        if (!$this->isUrlSafe($parsed_url['host'])) {
            return new WP_Error('aui_blocked_url', 'AUI: URL blocked for security reasons.');
        }

        // Set maximum file size (50MB)
        $max_size = 50 * 1024 * 1024;

        $args = [
            'user-agent' => 'WordPress/' . get_bloginfo('version') . '; ' . home_url(),
            'timeout' => 30,
            'redirection' => 3,  // Limit redirects
            'sslverify' => true,
            'headers' => [],
            'limit_response_size' => $max_size,
        ];

        if (isset($parsed_url['host'])) {
            $args['headers']['host'] = $parsed_url['host'];
        }

        $response = wp_remote_get($url, $args);

        if ($response instanceof WP_Error) {
            return $response;
        }

        if (isset($response['response']['code'], $response['body']) && $response['response']['code'] !== 200) {
            return new WP_Error('aui_download_failed', 'AUI: Image file bad response.');
        }

        // Check response size
        $body = $response['body'];
        if (strlen($body) > $max_size) {
            return new WP_Error('aui_file_too_large', 'AUI: Image file too large.');
        }

        if (empty($body)) {
            return new WP_Error('aui_empty_response', 'AUI: Empty response body.');
        }

        // Create secure temporary file
        $temp_file = $this->createSecureTempFile($body);
        if (is_wp_error($temp_file)) {
            return $temp_file;
        }

        $mime = wp_get_image_mime($temp_file);

        // Clean up temp file immediately after mime check
        if (file_exists($temp_file)) {
            unlink($temp_file);
        }

        if ($mime === false || strpos($mime, 'image/') !== 0) {
            return new WP_Error('aui_invalid_file', 'AUI: File type is not image.');
        }

        $image = [];
        $image['mime_type'] = $mime;
        $image['ext'] = self::getExtension($mime);
        $image['filename'] = $this->getFilename() . '.' . $image['ext'];
        $image['base_path'] = rtrim($this->getUploadDir('path'), DIRECTORY_SEPARATOR);
        $image['base_url'] = rtrim($this->getUploadDir('url'), '/');
        $image['path'] = $image['base_path'] . DIRECTORY_SEPARATOR . $image['filename'];
        $image['url'] = $image['base_url'] . '/' . $image['filename'];
        $c = 1;

        $sameFileExists = false;
        while (is_file($image['path'])) {
            if (sha1($response['body']) === sha1_file($image['path'])) {
                $sameFileExists = true;
                break;
            }

            $image['path'] = $image['base_path'] . DIRECTORY_SEPARATOR . $c . '_' . $image['filename'];
            $image['url'] = $image['base_url'] . '/' . $c . '_' . $image['filename'];
            $c++;
        }

        if ($sameFileExists) {
            return $image;
        }

        // Validate file path before writing
        if (!$this->isSecureFilePath($image['path'], $image['base_path'])) {
            return new WP_Error('aui_insecure_path', 'AUI: Insecure file path detected.');
        }

        // Write file securely
        $bytes_written = file_put_contents($image['path'], $body, LOCK_EX);
        if ($bytes_written === false || !is_file($image['path'])) {
            return new WP_Error('aui_image_save_failed', 'AUI: Image save to upload dir failed.');
        }

        $this->attachImage($image);

        if ($this->isNeedToResize() && ($resized = $this->resizeImage($image))) {
            $image['url'] = $resized['url'];
            $image['path'] = $resized['path'];
            $this->attachImage($image);
        }

        return $image;
    }

    /**
     * Attach image to post and media management
     * @param array $image
     * @return bool|int
     */
    public function attachImage($image)
    {
        $attachment = array(
            'guid' => $image['url'],
            'post_mime_type' => $image['mime_type'],
            'post_title' => $this->alt ?: preg_replace('/\.[^.]+$/', '', $image['filename']),
            'post_content' => '',
            'post_status' => 'inherit'
        );
        $attach_id = wp_insert_attachment($attachment, $image['path'], $this->post['ID']);
        if (!function_exists('wp_generate_attachment_metadata')) {
            include_once(ABSPATH . 'wp-admin/includes/image.php');
        }
        $attach_data = wp_generate_attachment_metadata($attach_id, $image['path']);

        return wp_update_attachment_metadata($attach_id, $attach_data);
    }

    /**
     * Resize image and returns resized url
     * @param $image
     * @return false|array
     */
    public function resizeImage($image)
    {
        $width = WpAutoUpload::getOption('max_width');
        $height = WpAutoUpload::getOption('max_height');
        $image_resized = image_make_intermediate_size($image['path'], $width, $height);

        if (!$image_resized) {
            return false;
        }

        return array(
            'url' => $image['base_url'] . '/' . urldecode($image_resized['file']),
            'path' => $image['base_path'] . DIRECTORY_SEPARATOR . urldecode($image_resized['file']),
        );
    }

    /**
     * Check image need to resize or not
     * @return bool
     */
    public function isNeedToResize()
    {
        return WpAutoUpload::getOption('max_width') || WpAutoUpload::getOption('max_height');
    }

    /**
     * Returns Image file extension by mime type
     * @param $mime
     * @return string|null
     */
    public static function getExtension($mime)
    {
        $mimes = array(
            'image/jpeg' => 'jpg',
            'image/png'  => 'png',
            'image/gif'  => 'gif',
            'image/bmp'  => 'bmp',
            'image/tiff' => 'tif',
            'image/webp' => 'webp',
        );

        return array_key_exists($mime, $mimes) ? $mimes[$mime] : null;
    }

    /**
     * Normalize and validate URL
     * @param $url
     * @return string|false
     */
    public static function normalizeUrl($url)
    {
        // Handle protocol-relative URLs
        if (preg_match('/^\/\/.*$/', $url)) {
            $url = 'https:' . $url;
        }

        // Validate the URL structure
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['scheme']) || !isset($parsed['host'])) {
            return false;
        }

        // Only allow HTTP and HTTPS
        if (!in_array(strtolower($parsed['scheme']), ['http', 'https'], true)) {
            return false;
        }

        // Rebuild URL to prevent injection
        $normalized = $parsed['scheme'] . '://' . $parsed['host'];

        if (isset($parsed['port'])) {
            $normalized .= ':' . $parsed['port'];
        }

        if (isset($parsed['path'])) {
            $normalized .= $parsed['path'];
        }

        if (isset($parsed['query'])) {
            $normalized .= '?' . $parsed['query'];
        }

        return $normalized;
    }
}
