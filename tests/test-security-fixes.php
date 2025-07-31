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
