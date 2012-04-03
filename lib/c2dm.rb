require 'net/https'

module C2DM
  class C2DMException < Exception
  end
  class QuotaExceeded < C2DMException
  end
  class DeviceQuotaExceeded < C2DMException
  end
  class InvalidRegistration < C2DMException
  end
  class NotRegistered < C2DMException
  end
  class MessageTooBig < C2DMException
  end
  class ServerUnavailableException < C2DMException
  end
  class InvalidAuthToken < C2DMException
  end
  
  def self.message_size data
    data.inject(0) do |sum, pair|
      sum + pair[0].to_s.length + pair[1].to_s.length
    end
  end
  
  def self.get_auth_token email, passwd
    auth_token_path = "/accounts/ClientLogin"
    data = ["accountType=HOSTED_OR_GOOGLE",
            "Email=#{email}",
            "Passwd=#{passwd}",
            "service=ac2dm",
            "source=jp.co.techfirm.c2dm"].join('&')
    
    headers = {'Content-Type' => 'application/x-www-form-urlencoded'}
    token = ''
    http = Net::HTTP.new(host = "www.google.com", port = 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.start do |http|
      response, body = http.post(auth_token_path, data, headers)
      case response
      when Net::HTTPOK
        token = body[/Auth=(.*)/, 1]
      else
        raise C2DMException.new("Invalid request #{response.body}")
      end
    end
    return token
  end
  
  class Sender
    def initialize email, passwd, cache_dir = nil
      @client = Client.new(fetch_auth_token(email, passwd, cache_dir))
    end
    
    def fetch_auth_token email, passwd, cache_dir = nil
      auth_token = ""
      @email = email
      @passwd = @passwd
      @cache_dir = cache_dir
      if cache_dir
        File.open(File.join(cache_dir,"auth_token_#{email}"), "r") do |file|
          auth_token = file.read
        end
      end
      
      if !auth_token || auth_token == ""
        auth_token = C2DM::get_auth_token(email, passwd)
        if cache_dir
          File.open(File.join(cache_dir,"auth_token_#{email}"), "w") do |file|
            file << auth_token
          end
        end
      end
      return auth_token
    end
    
    # retry once if invalid auth token error is raised
    def send_message registration_id, data, collapse_key=nil, delay_while_idle=false
      retried = false
      begin
        return @client.send_message registration_id, data, collapse_key, delay_while_idle
      rescue InvalidAuthToken => e
        raise e if retried
        @client.auth_token = fetch_auth_token(@email, @passwd, @cache_dir)
        retried = true
        retry
      end
    end
  end
  
  class Client
    attr_reader :auth_token
    attr_accessor :auth_token_callback

    def initialize token
      @auth_token = token
    end

    def auth_token= token
      before = @auth_token
      @auth_token = token
      @auth_token_callback.call(self, before, token) if @auth_token_callback
      token
    end

    def send_message registration_id, data, collapse_key=nil, delay_while_idle=false
      form_data = { 
        'registration_id' => registration_id,
        'collapse_key' => collapse_key || data.hash.to_s
      }

      form_data['delay_while_idle'] = '1' if delay_while_idle

      # c2dm service will accept any message where the combined length of keys and values is <= 1024
      data_length = C2DM::message_size data
      raise MessageTooBig.new("message length #{data_length} > 1024") if data_length > 1024

      data.each_pair do |key, value|
        form_data["data.#{key}"] = value
      end 

      headers = {'Authorization' => "GoogleLogin auth=#{@auth_token}" }
      http = Net::HTTP.new(host='android.apis.google.com', port=443)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.start

      req = Net::HTTP::Post.new('/c2dm/send', initheader = headers)
      req.set_form_data(form_data)

      response = http.request(req)

      if response['Update-Client-Auth']
        # Auth token is getting stale. Update cleint to the new one, and trigger a callback if it exists
        self.auth_token = response['Update-Client-Auth']
      end

      case response
      when Net::HTTPSuccess
        if response.body =~ /^Error=(.*)$/
          raise_error $1
        elsif response.body =~ /^id=(.*)$/
          $1
        else
          raise C2DMException.new "Invalid response body: #{response.body}"
        end
      when Net::HTTPForbidden, Net::HTTPUnauthorized
        raise InvalidAuthToken.new "Invalid or expired auth token."
      else
        raise C2DMException.new "Invalid response code: #{response.code}"
      end
    end

    private
    def raise_error error_name
      exception = case error_name
      when 'QuotaExceeded'
        QuotaExceeded
      when 'DeviceQuotaExceeded'
        DeviceQuotaExceeded
      when 'InvalidRegistration'
        InvalidRegistration
      when 'NotRegistered'
        NotRegistered
      when 'MessageTooBig'
        # This is unlikely since we check client side, but still possible.
        MessageTooBig
      else
        # MissingCollapseKey should never happen. Will just raise C2DMException
        C2DMException
      end

      raise exception.new("Server returned '#{error_name}'")
    end
  end
end


