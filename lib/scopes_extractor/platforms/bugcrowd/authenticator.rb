# frozen_string_literal: true

require 'rotp'

module ScopesExtractor
  module Platforms
    module Bugcrowd
      # Bugcrowd authenticator (Okta-based flow)
      class Authenticator
        IDENTITY_URL = 'https://identity.bugcrowd.com'
        OKTA_URL = 'https://login.hackers.bugcrowd.com'
        DASHBOARD_URL = 'https://bugcrowd.com/dashboard'

        OKTA_HEADERS = {
          'Accept' => 'application/json; okta-version=1.0.0',
          'Content-Type' => 'application/json',
          'X-Okta-User-Agent-Extended' => 'okta-auth-js/7.14.0 okta-signin-widget-7.43.1',
          'Origin' => OKTA_URL
        }.freeze

        def initialize(email:, password:, otp_secret:)
          @email = email
          @password = password
          @otp_secret = otp_secret
          @authenticated = false
        end

        def authenticated?
          @authenticated
        end

        def authenticate
          unless @email && @password && @otp_secret
            ScopesExtractor.logger.error '[Bugcrowd] Missing credentials (email, password, or OTP secret)'
            return false
          end

          ScopesExtractor.logger.debug '[Bugcrowd] Starting authentication flow'

          # Step 1: Get Okta login page and extract stateToken
          state_token = fetch_state_token
          return false unless state_token

          # Step 2: Introspect to get stateHandle
          state_handle = introspect(state_token)
          return false unless state_handle

          # Step 3: Identify (send email)
          state_handle = identify(state_handle)
          return false unless state_handle

          # Step 4: Password challenge
          state_handle = challenge_answer(state_handle, @password, 'Password')
          return false unless state_handle

          # Step 5: OTP challenge — returns success redirect URL
          otp_code = ROTP::TOTP.new(@otp_secret).now
          success_url = otp_challenge(state_handle, otp_code)
          return false unless success_url

          # Step 6: Follow token/redirect to establish session (Typhoeus follows 183/184 automatically)
          HTTP.get(success_url)

          # Step 7: Verify authentication
          establish_session
        rescue StandardError => e
          ScopesExtractor.logger.error "[Bugcrowd] Authentication error: #{e.message}"
          false
        end

        private

        def fetch_state_token
          response = HTTP.get("#{IDENTITY_URL}/login/hacker/oauth2/authorization/hacker")

          unless response.success?
            ScopesExtractor.logger.error "[Bugcrowd] Failed to fetch Okta login page: #{response.code}"
            return nil
          end

          match = response.body.match(/"stateToken"\s*:\s*"([^"]+)"/)
          unless match
            ScopesExtractor.logger.error '[Bugcrowd] Failed to extract stateToken'
            return nil
          end

          # Unescape JS hex sequences (e.g. \x2D -> -)
          token = match[1].gsub(/\\x([0-9A-Fa-f]{2})/) { [::Regexp.last_match(1).hex].pack('C') }
          ScopesExtractor.logger.debug '[Bugcrowd] stateToken extracted'
          token
        end

        def introspect(state_token)
          response = HTTP.post(
            "#{OKTA_URL}/idp/idx/introspect",
            body: { stateToken: state_token }.to_json,
            headers: OKTA_HEADERS.merge(
              'Accept' => 'application/ion+json; okta-version=1.0.0',
              'Content-Type' => 'application/ion+json; okta-version=1.0.0'
            )
          )

          unless response.success?
            ScopesExtractor.logger.error "[Bugcrowd] Introspect failed: #{response.code}"
            return nil
          end

          data = JSON.parse(response.body)
          state_handle = data['stateHandle']
          unless state_handle
            ScopesExtractor.logger.error '[Bugcrowd] No stateHandle in introspect response'
            return nil
          end

          ScopesExtractor.logger.debug '[Bugcrowd] stateHandle obtained'
          state_handle
        end

        def identify(state_handle)
          response = HTTP.post(
            "#{OKTA_URL}/idp/idx/identify",
            body: { identifier: @email, stateHandle: state_handle }.to_json,
            headers: OKTA_HEADERS
          )

          unless response.success?
            ScopesExtractor.logger.error "[Bugcrowd] Identify failed: #{response.code}"
            return nil
          end

          data = JSON.parse(response.body)
          ScopesExtractor.logger.debug '[Bugcrowd] Identify successful'
          data['stateHandle'] || state_handle
        end

        def challenge_answer(state_handle, passcode, step_name)
          response = HTTP.post(
            "#{OKTA_URL}/idp/idx/challenge/answer",
            body: { credentials: { passcode: passcode }, stateHandle: state_handle }.to_json,
            headers: OKTA_HEADERS
          )

          unless response.success?
            ScopesExtractor.logger.error "[Bugcrowd] #{step_name} challenge failed: #{response.code}"
            return nil
          end

          data = JSON.parse(response.body)
          ScopesExtractor.logger.debug "[Bugcrowd] #{step_name} challenge successful"
          data['stateHandle'] || state_handle
        end

        def otp_challenge(state_handle, otp_code)
          response = HTTP.post(
            "#{OKTA_URL}/idp/idx/challenge/answer",
            body: { credentials: { passcode: otp_code }, stateHandle: state_handle }.to_json,
            headers: OKTA_HEADERS
          )

          unless response.success?
            ScopesExtractor.logger.error "[Bugcrowd] OTP challenge failed: #{response.code}"
            return nil
          end

          data = JSON.parse(response.body)
          success_url = data.dig('success', 'href')
          unless success_url
            ScopesExtractor.logger.error '[Bugcrowd] No success redirect URL in OTP response'
            return nil
          end

          ScopesExtractor.logger.debug '[Bugcrowd] OTP challenge successful'
          success_url
        end

        def establish_session # rubocop:disable Naming/PredicateMethod
          response = HTTP.get(DASHBOARD_URL)

          if response.success? && response.body.include?('dashboard')
            ScopesExtractor.logger.debug '[Bugcrowd] Authentication successful'
            @authenticated = true
            true
          else
            ScopesExtractor.logger.error '[Bugcrowd] Authentication verification failed'
            false
          end
        end
      end
    end
  end
end
