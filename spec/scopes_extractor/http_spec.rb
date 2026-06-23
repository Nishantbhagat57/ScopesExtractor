# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ScopesExtractor::HTTP do
  def fake_response(code, headers: {}, body: '{}')
    instance_double(
      Typhoeus::Response,
      code: code,
      headers: headers,
      body: body,
      total_time: 0.1,
      success?: (200..299).cover?(code)
    )
  end

  before do
    # Avoid touching the real cookie jar and never sleep during tests.
    allow(described_class).to receive_messages(build_options: {}, wait: nil)
  end

  describe '#get' do
    it 'returns the response without retrying on success' do
      request = instance_double(Typhoeus::Request, run: fake_response(200))
      allow(Typhoeus::Request).to receive(:new).and_return(request)

      response = described_class.get('https://example.com')

      expect(response.code).to eq(200)
      expect(described_class).not_to have_received(:wait)
      expect(request).to have_received(:run).once
    end

    it 'retries on 429 and returns the first successful response' do
      request = instance_double(Typhoeus::Request)
      allow(request).to receive(:run).and_return(
        fake_response(429), fake_response(429), fake_response(200)
      )
      allow(Typhoeus::Request).to receive(:new).and_return(request)

      response = described_class.get('https://example.com')

      expect(response.code).to eq(200)
      expect(request).to have_received(:run).exactly(3).times
      expect(described_class).to have_received(:wait).twice
    end

    it 'retries on transient 5xx responses' do
      request = instance_double(Typhoeus::Request)
      allow(request).to receive(:run).and_return(fake_response(503), fake_response(200))
      allow(Typhoeus::Request).to receive(:new).and_return(request)

      expect(described_class.get('https://example.com').code).to eq(200)
      expect(described_class).to have_received(:wait).once
    end

    it 'gives up after the configured max attempts and returns the last response' do
      allow(ScopesExtractor::Config).to receive(:http_retry_max_attempts).and_return(2)
      request = instance_double(Typhoeus::Request, run: fake_response(429))
      allow(Typhoeus::Request).to receive(:new).and_return(request)

      response = described_class.get('https://example.com')

      expect(response.code).to eq(429)
      # 1 initial attempt + 2 retries
      expect(request).to have_received(:run).exactly(3).times
      expect(described_class).to have_received(:wait).twice
    end

    it 'does not retry on a non-retryable client error' do
      request = instance_double(Typhoeus::Request, run: fake_response(404))
      allow(Typhoeus::Request).to receive(:new).and_return(request)

      expect(described_class.get('https://example.com').code).to eq(404)
      expect(described_class).not_to have_received(:wait)
    end
  end

  describe '#retryable?' do
    it 'is true for 429 and 5xx codes' do
      [429, 500, 502, 503, 504].each do |code|
        expect(described_class.retryable?(fake_response(code))).to be(true)
      end
    end

    it 'is false for success and other client errors' do
      [200, 301, 400, 401, 404].each do |code|
        expect(described_class.retryable?(fake_response(code))).to be(false)
      end
    end
  end

  describe '#retry_delay' do
    before do
      allow(ScopesExtractor::Config).to receive_messages(
        http_retry_base_delay: 3, http_retry_max_delay: 70
      )
    end

    it 'honours a numeric Retry-After header over the backoff' do
      response = fake_response(429, headers: { 'Retry-After' => '42' })
      expect(described_class.retry_delay(response, 0)).to eq(42.0)
    end

    it 'grows exponentially and stays within [base, cap] bounds' do
      delays = (0..5).map { |attempt| described_class.retry_delay(fake_response(429), attempt) }

      # base=3 → unjittered curve 3,6,12,24,48,70 ; jitter adds 0..base on top, capped.
      expect(delays[0]).to be_between(3, 6)
      expect(delays[1]).to be_between(6, 9)
      expect(delays.last).to be <= 70
      expect(delays.last).to be_within(3).of(70)
    end
  end

  describe '#parse_retry_after' do
    it 'parses a numeric seconds value (case-insensitive header)' do
      expect(described_class.parse_retry_after(fake_response(429, headers: { 'retry-after' => '30' }))).to eq(30.0)
    end

    it 'caps the value at http_retry_max_delay' do
      allow(ScopesExtractor::Config).to receive(:http_retry_max_delay).and_return(70)
      expect(described_class.parse_retry_after(fake_response(429, headers: { 'Retry-After' => '600' }))).to eq(70.0)
    end

    it 'returns nil when the header is absent or non-numeric' do
      expect(described_class.parse_retry_after(fake_response(429))).to be_nil
      expect(described_class.parse_retry_after(fake_response(429, headers: { 'Retry-After' => 'soon' }))).to be_nil
    end
  end
end
