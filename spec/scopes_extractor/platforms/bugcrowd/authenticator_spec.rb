# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ScopesExtractor::Platforms::Bugcrowd::Authenticator do
  let(:email) { 'test@example.com' }
  let(:password) { 'test_password' }
  let(:otp_secret) { 'BASE32SECRET' }
  let(:authenticator) { described_class.new(email: email, password: password, otp_secret: otp_secret) }

  let(:state_token) { 'eyJ6aXAiOiJERUYi.test_state_token' }
  let(:state_handle) { '02.id.test_state_handle' }
  let(:updated_state_handle) { '02.id.updated_state_handle' }
  let(:success_redirect_url) { 'https://login.hackers.bugcrowd.com/login/token/redirect?stateToken=02.id.test_state_handle' }

  let(:okta_login_page_body) do
    "<html><script>var oktaData = {\"stateToken\":\"#{state_token}\"};</script></html>"
  end

  describe '#initialize' do
    it 'sets email' do
      expect(authenticator.instance_variable_get(:@email)).to eq(email)
    end

    it 'starts unauthenticated' do
      expect(authenticator.authenticated?).to be false
    end
  end

  describe '#authenticated?' do
    it 'returns false initially' do
      expect(authenticator.authenticated?).to be false
    end
  end

  describe '#authenticate' do
    let(:okta_page_response) do
      double('Response', success?: true, code: 200, body: okta_login_page_body)
    end
    let(:introspect_response) do
      double('Response', success?: true, code: 200, body: { stateHandle: state_handle }.to_json)
    end
    let(:identify_response) do
      double('Response', success?: true, code: 200, body: { stateHandle: updated_state_handle }.to_json)
    end
    let(:password_challenge_response) do
      double('Response', success?: true, code: 200, body: { stateHandle: updated_state_handle }.to_json)
    end
    let(:otp_challenge_response) do
      double('Response', success?: true, code: 200,
             body: { stateHandle: updated_state_handle,
                     success: { name: 'success-redirect', href: success_redirect_url } }.to_json)
    end
    let(:token_redirect_response) do
      double('Response', success?: true, code: 200, body: '')
    end
    let(:dashboard_response) do
      double('Response', success?: true, code: 200, body: '<html>dashboard</html>')
    end

    context 'when credentials are missing' do
      context 'when email is missing' do
        let(:email) { nil }

        it 'returns false' do
          expect(authenticator.authenticate).to be false
        end

        it 'logs error message' do
          expect(ScopesExtractor.logger).to receive(:error)
            .with('[Bugcrowd] Missing credentials (email, password, or OTP secret)')
          authenticator.authenticate
        end
      end

      context 'when password is missing' do
        let(:password) { nil }

        it 'returns false' do
          expect(authenticator.authenticate).to be false
        end
      end

      context 'when OTP secret is missing' do
        let(:otp_secret) { nil }

        it 'returns false' do
          expect(authenticator.authenticate).to be false
        end
      end
    end

    context 'when authentication flow succeeds' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(okta_page_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/introspect'), any_args)
          .and_return(introspect_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/identify'), any_args)
          .and_return(identify_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/challenge/answer'), any_args)
          .and_return(password_challenge_response, otp_challenge_response)
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(success_redirect_url)
          .and_return(token_redirect_response)
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with('https://bugcrowd.com/dashboard')
          .and_return(dashboard_response)
      end

      it 'returns true' do
        expect(authenticator.authenticate).to be true
      end

      it 'sets authenticated to true' do
        authenticator.authenticate
        expect(authenticator.authenticated?).to be true
      end

      it 'logs debug messages' do
        expect(ScopesExtractor.logger).to receive(:debug).with('[Bugcrowd] Starting authentication flow')
        expect(ScopesExtractor.logger).to receive(:debug).with('[Bugcrowd] stateToken extracted')
        expect(ScopesExtractor.logger).to receive(:debug).with('[Bugcrowd] stateHandle obtained')
        expect(ScopesExtractor.logger).to receive(:debug).with('[Bugcrowd] Identify successful')
        expect(ScopesExtractor.logger).to receive(:debug).with('[Bugcrowd] Password challenge successful')
        expect(ScopesExtractor.logger).to receive(:debug).with('[Bugcrowd] OTP challenge successful')
        expect(ScopesExtractor.logger).to receive(:debug).with('[Bugcrowd] Authentication successful')
        authenticator.authenticate
      end
    end

    context 'when Okta login page fetch fails' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(double('Response', success?: false, code: 500))
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with(/Failed to fetch Okta login page/)
        authenticator.authenticate
      end
    end

    context 'when stateToken extraction fails' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(double('Response', success?: true, code: 200, body: '<html>no token here</html>'))
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with('[Bugcrowd] Failed to extract stateToken')
        authenticator.authenticate
      end
    end

    context 'when introspect fails' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(okta_page_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/introspect'), any_args)
          .and_return(double('Response', success?: false, code: 400))
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with(/Introspect failed: 400/)
        authenticator.authenticate
      end
    end

    context 'when identify fails' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(okta_page_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/introspect'), any_args)
          .and_return(introspect_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/identify'), any_args)
          .and_return(double('Response', success?: false, code: 401))
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with(/Identify failed: 401/)
        authenticator.authenticate
      end
    end

    context 'when password challenge fails' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(okta_page_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/introspect'), any_args)
          .and_return(introspect_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/identify'), any_args)
          .and_return(identify_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/challenge/answer'), any_args)
          .and_return(double('Response', success?: false, code: 401))
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with(/Password challenge failed: 401/)
        authenticator.authenticate
      end
    end

    context 'when OTP challenge fails' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(okta_page_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/introspect'), any_args)
          .and_return(introspect_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/identify'), any_args)
          .and_return(identify_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/challenge/answer'), any_args)
          .and_return(
            password_challenge_response,
            double('Response', success?: false, code: 401)
          )
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with(/OTP challenge failed: 401/)
        authenticator.authenticate
      end
    end

    context 'when dashboard verification fails' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(okta_page_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/introspect'), any_args)
          .and_return(introspect_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/identify'), any_args)
          .and_return(identify_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/challenge/answer'), any_args)
          .and_return(password_challenge_response, otp_challenge_response)
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(success_redirect_url)
          .and_return(token_redirect_response)
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with('https://bugcrowd.com/dashboard')
          .and_return(double('Response', success?: true, code: 200, body: '<html>Not logged in</html>'))
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with('[Bugcrowd] Authentication verification failed')
        authenticator.authenticate
      end
    end

    context 'when an exception occurs' do
      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_raise(StandardError, 'Network error')
      end

      it 'returns false' do
        expect(authenticator.authenticate).to be false
      end

      it 'logs error message' do
        expect(ScopesExtractor.logger).to receive(:error).with(/Authentication error: Network error/)
        authenticator.authenticate
      end
    end

    context 'with hex-escaped stateToken' do
      let(:okta_login_page_body) do
        '<html><script>var oktaData = {"stateToken":"abc\\x2Ddef\\x2Dghi"};</script></html>'
      end

      before do
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(include('oauth2/authorization/hacker'))
          .and_return(okta_page_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/introspect'), any_args) do |_url, **kwargs|
            body = JSON.parse(kwargs[:body])
            expect(body['stateToken']).to eq('abc-def-ghi')
            introspect_response
          end
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/identify'), any_args)
          .and_return(identify_response)
        allow(ScopesExtractor::HTTP).to receive(:post)
          .with(include('/idp/idx/challenge/answer'), any_args)
          .and_return(password_challenge_response, otp_challenge_response)
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with(success_redirect_url)
          .and_return(token_redirect_response)
        allow(ScopesExtractor::HTTP).to receive(:get)
          .with('https://bugcrowd.com/dashboard')
          .and_return(dashboard_response)
      end

      it 'unescapes hex sequences in stateToken' do
        expect(authenticator.authenticate).to be true
      end
    end
  end
end
