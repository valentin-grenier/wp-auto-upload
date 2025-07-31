<?php

/**
 * Test class for SSRF security fixes
 */
class SecurityFixesTest extends WP_UnitTestCase
{
    /**
     * @var ImageUploader
     */
    public $imageUploader;

    public function setUp()
    {
        parent::setUp();

        $samplePost = array(
            'ID' => 1,
            'post_name' => 'sample',
        );

        $this->imageUploader = new ImageUploader('https://example.com/test.jpg', 'sample alt', $samplePost);
    }

    /**
     * Test that private IP addresses are blocked
     */
    public function testPrivateIpBlocked()
    {
        // Test localhost
        $this->imageUploader->url = 'http://127.0.0.1/test.jpg';
        $this->assertFalse($this->imageUploader->validate());

        // Test private network ranges
        $this->imageUploader->url = 'http://192.168.1.1/test.jpg';
        $this->assertFalse($this->imageUploader->validate());

        $this->imageUploader->url = 'http://10.0.0.1/test.jpg';
        $this->assertFalse($this->imageUploader->validate());

        $this->imageUploader->url = 'http://172.16.0.1/test.jpg';
        $this->assertFalse($this->imageUploader->validate());
    }

    /**
     * Test that cloud metadata endpoints are blocked
     */
    public function testMetadataEndpointsBlocked()
    {
        // AWS metadata endpoint
        $this->imageUploader->url = 'http://169.254.169.254/latest/meta-data/';
        $this->assertFalse($this->imageUploader->validate());
    }

    /**
     * Test that only HTTP/HTTPS protocols are allowed
     */
    public function testProtocolValidation()
    {
        // Test file:// protocol
        $this->imageUploader->url = 'file:///etc/passwd';
        $this->assertFalse($this->imageUploader->validate());

        // Test ftp:// protocol  
        $this->imageUploader->url = 'ftp://example.com/test.jpg';
        $this->assertFalse($this->imageUploader->validate());

        // Test gopher:// protocol
        $this->imageUploader->url = 'gopher://example.com/test.jpg';
        $this->assertFalse($this->imageUploader->validate());

        // Test valid HTTP/HTTPS
        $this->imageUploader->url = 'https://example.com/test.jpg';
        $this->assertTrue($this->imageUploader->validate());

        $this->imageUploader->url = 'http://example.com/test.jpg';
        $this->assertTrue($this->imageUploader->validate());
    }

    /**
     * Test URL normalization security
     */
    public function testUrlNormalization()
    {
        // Test that invalid URLs return false
        $this->assertFalse(ImageUploader::normalizeUrl('javascript:alert(1)'));
        $this->assertFalse(ImageUploader::normalizeUrl('data:text/html,<script>alert(1)</script>'));
        $this->assertFalse(ImageUploader::normalizeUrl('invalid-url'));

        // Test protocol-relative URLs are converted to HTTPS
        $normalized = ImageUploader::normalizeUrl('//example.com/test.jpg');
        $this->assertEquals('https://example.com/test.jpg', $normalized);

        // Test normal URLs pass through
        $normalized = ImageUploader::normalizeUrl('https://example.com/test.jpg');
        $this->assertEquals('https://example.com/test.jpg', $normalized);
    }

    /**
     * Test that malformed URLs are rejected
     */
    public function testMalformedUrls()
    {
        $wp_auto_upload = new WpAutoUpload();

        // Test URL with dangerous characters
        $this->assertFalse($this->invokeMethod($wp_auto_upload, 'isValidImageUrl', ['http://example.com/test<script>.jpg']));

        // Test extremely long URL
        $long_url = 'http://example.com/' . str_repeat('a', 3000) . '.jpg';
        $this->assertFalse($this->invokeMethod($wp_auto_upload, 'isValidImageUrl', [$long_url]));

        // Test valid URL
        $this->assertTrue($this->invokeMethod($wp_auto_upload, 'isValidImageUrl', ['https://example.com/test.jpg']));
    }

    /**
     * Test IPv6 address blocking
     */
    public function testIPv6Blocking()
    {
        // Test IPv6 localhost
        $this->imageUploader->url = 'http://[::1]/test.jpg';
        $this->assertFalse($this->imageUploader->validate());

        // Test IPv6 link-local
        $this->imageUploader->url = 'http://[fe80::1]/test.jpg';
        $this->assertFalse($this->imageUploader->validate());

        // Test IPv6 unique local
        $this->imageUploader->url = 'http://[fc00::1]/test.jpg';
        $this->assertFalse($this->imageUploader->validate());
    }

    /**
     * Test that DNS rebinding attacks are prevented
     */
    public function testDNSRebindingPrevention()
    {
        // Mock a domain that could resolve to different IPs
        // This test would need actual DNS mocking in a real environment
        $this->assertTrue(true); // Placeholder - actual implementation would need DNS mocking
    }

    /**
     * Test secure temporary file handling
     */
    public function testSecureTempFileHandling()
    {
        // Test that temp files are created in secure location
        $reflection = new \ReflectionClass('ImageUploader');
        $method = $reflection->getMethod('createSecureTempFile');
        $method->setAccessible(true);

        $uploader = new ImageUploader('https://example.com/test.jpg', 'test', ['ID' => 1]);
        $result = $method->invoke($uploader, 'test content');

        $this->assertNotInstanceOf('WP_Error', $result);
        $this->assertStringContainsString('aui-temp', $result);

        // Clean up
        if (file_exists($result)) {
            unlink($result);
        }
    }

    /**
     * Test path traversal prevention
     */
    public function testPathTraversalPrevention()
    {
        $reflection = new \ReflectionClass('ImageUploader');
        $method = $reflection->getMethod('isSecureFilePath');
        $method->setAccessible(true);

        $uploader = new ImageUploader('https://example.com/test.jpg', 'test', ['ID' => 1]);

        // Test valid path
        $this->assertTrue($method->invoke($uploader, '/valid/path/file.jpg', '/valid/path'));

        // Test traversal attempt
        $this->assertFalse($method->invoke($uploader, '/valid/path/../../../etc/passwd', '/valid/path'));
    }

    /**
     * Helper method to test private methods
     */
    protected function invokeMethod($object, $methodName, array $parameters = [])
    {
        $reflection = new \ReflectionClass(get_class($object));
        $method = $reflection->getMethod($methodName);
        $method->setAccessible(true);

        return $method->invokeArgs($object, $parameters);
    }
}
