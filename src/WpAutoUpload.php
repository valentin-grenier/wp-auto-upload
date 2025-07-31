<?php

require 'ImageUploader.php';

/**
 * Wordpress Auto Upload Images
 * @link http://wordpress.org/plugins/auto-upload-images/
 * @link https://github.com/airani/wp-auto-upload
 * @author Ali Irani <ali@irani.im>
 */
class WpAutoUpload
{
    const WP_OPTIONS_KEY = 'aui-setting';

    private static $_options;

    /**
     * WP_Auto_Upload Run.
     * Set default variables and options
     * Add wordpress actions
     */
    public function run()
    {
        add_action('plugins_loaded', array($this, 'initTextdomain'));
        add_action('admin_menu', array($this, 'addAdminMenu'));
        add_action('wp_insert_post_data', array($this, 'savePost'), 10, 2);

        // Register cleanup task
        add_action('wp_scheduled_delete', array('ImageUploader', 'cleanupTempFiles'));
    }

    /**
     * Initial plugin textdomain for translation files
     */
    public function initTextdomain()
    {
        load_plugin_textdomain('auto-upload-images', false, basename(WPAUI_DIR) . '/src/lang');
    }

    /**
     * Automatically upload external images of a post to Wordpress upload directory
     * call by wp_insert_post_data filter
     * @param array data An array of slashed post data
     * @param array $postarr An array of sanitized, but otherwise unmodified post data
     * @return array $data
     */
    public function savePost($data, $postarr)
    {
        if (
            wp_is_post_revision($postarr['ID']) ||
            wp_is_post_autosave($postarr['ID']) ||
            (defined('DOING_AJAX') && DOING_AJAX) ||
            (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE)
        ) {
            return $data;
        }

        if ($content = $this->save($postarr)) {
            $data['post_content'] = $content;
        }
        return $data;
    }

    /**
     * Upload images and save new urls
     * @return string filtered content
     */
    public function save($postarr)
    {
        $excludePostTypes = self::getOption('exclude_post_types');
        if (is_array($excludePostTypes) && in_array($postarr['post_type'], $excludePostTypes, true)) {
            return false;
        }

        $content = $postarr['post_content'];
        $images = $this->findAllImageUrls(stripslashes($content));

        if (count($images) == 0) {
            return false;
        }

        foreach ($images as $image) {
            $uploader = new ImageUploader($image['url'], $image['alt'], $postarr);
            if ($uploadedImage = $uploader->save()) {
                $urlParts = parse_url($uploadedImage['url']);
                $base_url = $uploader::getHostUrl(null, true, true);
                $image_url = $base_url . $urlParts['path'];

                // Safely escape the URLs for regex replacement
                $old_url_escaped = preg_quote($image['url'], '/');
                $new_url_escaped = esc_url($image_url);

                // Replace the image URL
                $content = preg_replace('/' . $old_url_escaped . '/', $new_url_escaped, $content);

                // Safely replace alt attribute
                if (!empty($image['alt'])) {
                    $old_alt_escaped = preg_quote($image['alt'], '/');
                    $new_alt_escaped = esc_attr($uploader->getAlt());
                    $content = preg_replace('/alt=["\']' . $old_alt_escaped . '["\']/', "alt=\"{$new_alt_escaped}\"", $content);
                }
            }
        }
        return $content;
    }

    /**
     * Find image urls in content and retrieve urls by array
     * @param $content
     * @return array
     */
    public function findAllImageUrls($content)
    {
        $urls1 = array();
        preg_match_all('/<img[^>]*srcset=["\']([^"\']*)[^"\']*["\'][^>]*>/i', $content, $srcsets, PREG_SET_ORDER);
        if (count($srcsets) > 0) {
            $count = 0;
            foreach ($srcsets as $key => $srcset) {
                preg_match_all('/(https?:)?\/\/[^\s,]+/i', $srcset[1], $srcsetUrls, PREG_SET_ORDER);
                if (count($srcsetUrls) == 0) {
                    continue;
                }
                foreach ($srcsetUrls as $srcsetUrl) {
                    // Basic URL validation before adding to array
                    if ($this->isValidImageUrl($srcsetUrl[0])) {
                        $urls1[$count][] = $srcset[0];
                        $urls1[$count][] = $srcsetUrl[0];
                        $count++;
                    }
                }
            }
        }

        preg_match_all('/<img[^>]*src=["\']([^"\']*)[^"\']*["\'][^>]*>/i', $content, $urls, PREG_SET_ORDER);
        $urls = array_merge($urls, $urls1);

        if (count($urls) == 0) {
            return array();
        }
        foreach ($urls as $index => &$url) {
            // Basic URL validation before processing
            if (!$this->isValidImageUrl($url[1])) {
                unset($urls[$index]);
                continue;
            }
            $images[$index]['alt'] = preg_match('/<img[^>]*alt=["\']([^"\']*)[^"\']*["\'][^>]*>/i', $url[0], $alt) ? $alt[1] : null;
            $images[$index]['url'] = $url = $url[1];
        }
        foreach (array_unique($urls) as $index => $url) {
            if (isset($images[$index])) {
                $unique_array[] = $images[$index];
            }
        }
        return isset($unique_array) ? $unique_array : array();
    }

    /**
     * Basic validation for image URLs to prevent malicious URLs
     * @param string $url
     * @return bool
     */
    private function isValidImageUrl($url)
    {
        // Basic URL structure validation
        if (empty($url) || !is_string($url)) {
            return false;
        }

        // Remove common URL artifacts
        $url = trim($url);

        // Must start with http:// or https:// or be protocol-relative
        if (!preg_match('/^(https?:)?\/\//', $url)) {
            return false;
        }

        // Basic length check to prevent extremely long URLs
        if (strlen($url) > 2048) {
            return false;
        }

        // Check for suspicious characters that might indicate injection
        if (preg_match('/[<>"\']/', $url)) {
            return false;
        }

        return true;
    }

    /**
     * Add settings page under options menu
     */
    public function addAdminMenu()
    {
        add_options_page(
            __('Auto Upload Images Settings', 'auto-upload-images'),
            __('Auto Upload Images', 'auto-upload-images'),
            'manage_options',
            'auto-upload',
            array($this, 'settingPage')
        );
    }

    /**
     * Returns options in an array
     * @return array
     */
    public static function getOptions()
    {
        if (static::$_options) {
            return static::$_options;
        }
        $defaults = array(
            'base_url' => get_bloginfo('url'),
            'image_name' => '%filename%',
            'alt_name' => '%image_alt%',
        );
        return static::$_options = wp_parse_args(get_option(self::WP_OPTIONS_KEY), $defaults);
    }

    /**
     * Reset options to default options
     * @return bool
     */
    public static function resetOptionsToDefaults()
    {
        $defaults = array(
            'base_url' => get_bloginfo('url'),
            'image_name' => '%filename%',
            'alt_name' => '%image_alt%',
        );
        static::$_options = $defaults;
        return update_option(self::WP_OPTIONS_KEY, $defaults);
    }

    /**
     * Return an option with specific key
     * @param $key
     * @return mixed
     */
    public static function getOption($key, $default = null)
    {
        $options = static::getOptions();
        if (isset($options[$key]) === false) {
            return $default;
        }
        return $options[$key];
    }

    /**
     * Returns fixed and replace deprecated patterns
     * @param $pattern
     * @return string
     */
    public function replaceDeprecatedPatterns($pattern)
    {
        preg_match_all('/%(date|day)%/', $pattern, $rules);

        $patterns = array(
            '%date%' => '%today_date%',
            '%day%' => '%today_day%',
        );

        if ($rules[0]) {
            foreach ($rules[0] as $rule) {
                // Use str_replace instead of preg_replace to prevent regex injection
                $replacement = array_key_exists($rule, $patterns) ? $patterns[$rule] : $rule;
                $pattern = str_replace($rule, $replacement, $pattern);
            }
        }

        return $pattern;
    }

    /**
     * Settings page contents
     */
    public function settingPage()
    {
        if (isset($_POST['submit']) && check_admin_referer('aui_settings')) {
            $textFields = array('base_url', 'image_name', 'alt_name', 'max_width', 'max_height');
            foreach ($textFields as $field) {
                if (array_key_exists($field, $_POST) && $_POST[$field]) {
                    if ($field === 'image_name' || $field === 'alt_name') {
                        $pattern = $this->replaceDeprecatedPatterns($_POST[$field]);
                        // Additional validation for pattern fields
                        if (!$this->isValidPattern($pattern)) {
                            add_action('admin_notices', function () use ($field) {
                                echo '<div class="notice notice-error"><p>' .
                                    sprintf(__('Invalid pattern provided for %s. Please use only allowed pattern codes.', 'auto-upload-images'), $field) .
                                    '</p></div>';
                            });
                            continue;
                        }
                        static::$_options[$field] = sanitize_text_field($pattern);
                    }
                    // Additional validation for base_url field
                    elseif ($field === 'base_url') {
                        $base_url = sanitize_text_field($_POST[$field]);
                        if (!$this->isValidBaseUrl($base_url)) {
                            add_action('admin_notices', function () {
                                echo '<div class="notice notice-error"><p>' .
                                    __('Invalid base URL provided. Please use a valid HTTP/HTTPS URL.', 'auto-upload-images') .
                                    '</p></div>';
                            });
                            continue;
                        }
                        static::$_options[$field] = $base_url;
                    } else {
                        static::$_options[$field] = sanitize_text_field($_POST[$field]);
                    }
                }
            }
            if (array_key_exists('exclude_urls', $_POST) && $_POST['exclude_urls']) {
                // Validate excluded URLs
                $exclude_urls = sanitize_textarea_field($_POST['exclude_urls']);
                if ($this->validateExcludeUrls($exclude_urls)) {
                    static::$_options['exclude_urls'] = $exclude_urls;
                } else {
                    add_action('admin_notices', function () {
                        echo '<div class="notice notice-error"><p>' .
                            __('One or more excluded URLs are invalid. Please check the format.', 'auto-upload-images') .
                            '</p></div>';
                    });
                }
            }
            if (array_key_exists('exclude_post_types', $_POST) && $_POST['exclude_post_types']) {
                static::$_options['exclude_post_types'] = array();
                foreach ($_POST['exclude_post_types'] as $typ) {
                    // Validate post type exists
                    if (post_type_exists(sanitize_text_field($typ))) {
                        static::$_options['exclude_post_types'][] = sanitize_text_field($typ);
                    }
                }
            }
            update_option(self::WP_OPTIONS_KEY, static::$_options);
            $message = __('Settings Saved.', 'auto-upload-images');
        }

        if (isset($_POST['reset']) && check_admin_referer('aui_settings') && self::resetOptionsToDefaults()) {
            $message = __('Successfully settings reset to defaults.', 'auto-upload-images');
        }

        include_once('setting-page.php');
    }

    /**
     * Validate base URL setting
     * @param string $url
     * @return bool
     */
    private function isValidBaseUrl($url)
    {
        if (empty($url)) {
            return false;
        }

        // Allow relative URLs like "/"
        if ($url === '/') {
            return true;
        }

        // For full URLs, validate structure
        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['scheme']) || !isset($parsed['host'])) {
            return false;
        }

        // Only allow HTTP and HTTPS
        if (!in_array(strtolower($parsed['scheme']), ['http', 'https'], true)) {
            return false;
        }

        return true;
    }

    /**
     * Validate excluded URLs list
     * @param string $urls_text
     * @return bool
     */
    private function validateExcludeUrls($urls_text)
    {
        if (empty($urls_text)) {
            return true;
        }

        $urls = explode("\n", $urls_text);
        foreach ($urls as $url) {
            $url = trim($url);
            if (empty($url)) {
                continue;
            }

            $parsed = parse_url($url);
            if (!$parsed || !isset($parsed['host'])) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate pattern to ensure it only contains allowed pattern codes
     * @param string $pattern
     * @return bool
     */
    private function isValidPattern($pattern)
    {
        // List of allowed pattern codes
        $allowed_patterns = [
            '%filename%',
            '%image_alt%',
            '%today_date%',
            '%year%',
            '%month%',
            '%today_day%',
            '%post_date%',
            '%post_year%',
            '%post_month%',
            '%post_day%',
            '%url%',
            '%random%',
            '%timestamp%',
            '%post_id%',
            '%postname%'
        ];

        // Find all pattern codes in the input
        preg_match_all('/%[^%]*%/', $pattern, $matches);

        if (!empty($matches[0])) {
            foreach ($matches[0] as $match) {
                if (!in_array($match, $allowed_patterns, true)) {
                    return false;
                }
            }
        }

        // Check for potentially dangerous content
        if (preg_match('/[<>"\'\\\]/', $pattern)) {
            return false;
        }

        // Length limit
        if (strlen($pattern) > 200) {
            return false;
        }

        return true;
    }
}
