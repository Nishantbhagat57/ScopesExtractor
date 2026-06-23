# frozen_string_literal: true

require 'typhoeus'
require 'tempfile'

module ScopesExtractor
  module HTTP
    # HTTP status codes that are worth retrying with backoff.
    # 429 = rate limited, 5xx = transient server-side errors.
    RETRYABLE_CODES = [429, 500, 502, 503, 504].freeze

    class << self
      attr_reader :hydra, :cookie_file

      def setup
        @hydra = Typhoeus::Hydra.new(max_concurrency: 10)
        @cookie_file = Tempfile.new(['scopes_extractor_cookies', '.txt'])
        @cookie_file.close # Close but don't unlink - Typhoeus needs the file path
        ScopesExtractor.logger.info "HTTP client initialized with User-Agent: #{Config.user_agent}"
      end

      def cleanup
        @cookie_file&.unlink
      end

      def clear_cookies
        return unless @cookie_file

        # Truncate the cookie file to clear all cookies
        File.truncate(@cookie_file.path, 0)
        ScopesExtractor.logger.debug 'Cookie jar cleared'
      end

      def get(url, headers: {}, timeout: nil)
        request(:get, url, headers: headers, timeout: timeout)
      end

      def post(url, body:, headers: {}, timeout: nil)
        request(:post, url, body: body, headers: headers, timeout: timeout)
      end

      def retryable?(response)
        RETRYABLE_CODES.include?(response.code)
      end

      # Computes how long to wait before the next retry.
      # Honours a server-provided Retry-After header when present, otherwise
      # falls back to capped exponential backoff with positive jitter.
      # The jitter desynchronizes clients sharing the same token/IP, which is
      # the main cause of repeated 429s when several tools run concurrently.
      # @return [Float] delay in seconds
      def retry_delay(response, attempt)
        retry_after = parse_retry_after(response)
        return retry_after if retry_after

        base = Config.http_retry_base_delay.to_f
        cap = Config.http_retry_max_delay.to_f

        backoff = [base * (2**attempt), cap].min
        [backoff + (rand * base), cap].min
      end

      # Parses the Retry-After header (delay in seconds form only).
      # Capped to http_retry_max_delay to keep waits bounded.
      # @return [Float, nil] seconds to wait, or nil if absent/unparseable
      def parse_retry_after(response)
        headers = response.headers || {}
        value = headers['Retry-After'] || headers['retry-after']
        return nil unless value.to_s.strip.match?(/\A\d+\z/)

        [value.to_i, Config.http_retry_max_delay].min.to_f
      end

      # Extracted for testability (stubbed in specs to avoid real sleeping).
      def wait(seconds)
        sleep(seconds)
      end

      private

      def request(method, url, body: nil, headers: {}, timeout: nil)
        options = build_options(body, headers, timeout)
        max_attempts = Config.http_retry_max_attempts
        attempt = 0

        loop do
          response = Typhoeus::Request.new(url, options.merge(method: method)).run
          log_request(method, url, response)

          return response unless retryable?(response) && attempt < max_attempts

          delay = retry_delay(response, attempt)
          ScopesExtractor.logger.warn(
            "#{method.to_s.upcase} #{url} → #{response.code}, retrying in #{delay.round(1)}s " \
            "(attempt #{attempt + 1}/#{max_attempts})"
          )
          wait(delay)
          attempt += 1
        end
      end

      def build_options(body, headers, timeout)
        options = {
          headers: default_headers.merge(headers),
          timeout: timeout || Config.timeout,
          followlocation: true,
          cookiefile: @cookie_file.path,
          cookiejar: @cookie_file.path
        }

        options[:body] = body if body
        options[:proxy] = Config.proxy if Config.proxy
        options
      end

      def default_headers
        {
          'User-Agent' => Config.user_agent
        }
      end

      def log_request(method, url, response)
        method_str = method.to_s.upcase
        status = response.code
        time = response.total_time.round(2)

        if response.success?
          ScopesExtractor.logger.debug "#{method_str} #{url} → #{status} (#{time}s)"
        else
          ScopesExtractor.logger.warn "#{method_str} #{url} → #{status} (#{time}s)"
        end
      end
    end
  end
end
