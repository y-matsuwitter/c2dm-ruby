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
  
  def self.get_auth_token email, passwd, source
    auth_token_path = "/accounts/ClientLogin"
    data = ["accountType=GOOGLE",
            "Email=#{email}",
            "Passwd=#{passwd}",
            "service=ac2dm",
            "source=#{source}"].join('&')
    
    headers = {'Content-Type' => 'application/x-www-form-urlencoded'}
    token = ''
    http = Net::HTTP.new(host = "www.google.com", port = 443)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.start do |http|
      response= http.post(auth_token_path, data, headers)
      body = response.body
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
    def initialize email, passwd, source, cache_dir = nil
      @client = Client.new(fetch_auth_token(email, passwd, source, cache_dir))
      @client.auth_token_callback = lambda do |client, old , token|
        reflesh_cache(token)
      end
    end
    
    def fetch_auth_token email, passwd, source, cache_dir = nil
      auth_token = ""
      @email = email
      @passwd = passwd
      @source = source
      @cache_dir = cache_dir
      if cache_dir
        File.open(File.join(cache_dir,"auth_token_#{email}"), "r") do |file|
          auth_token = file.read
        end
      end
      
      if !auth_token || auth_token == ""
        auth_token = C2DM::get_auth_token(email, passwd, source)
        if cache_dir
          File.open(File.join(cache_dir,"auth_token_#{email}"), "w") do |file|
            file << auth_token
          end
        end
      end
      return auth_token
    end
    
    def send_messages messages
      succeeded = @client.send_messages messages
      if succeeded.size != messages.size
        to_retry = []
        messages.each do |m|
          to_retry.push(m) if !succeeded.include?(m)
        end
        @client.auth_token = fetch_auth_token(@email, @passwd,@source, @cache_dir)
        succeeded = @client.send_messages to_retry
        raise InvalidAuthToken.new("Invalid Auth Token") if succeeded.size != to_retry.size
      end
      return messages
    end
    
    # retry once if invalid auth token error is raised
    def send_message registration_id, data, collapse_key=nil, delay_while_idle=false
      retried = false
      begin
        return @client.send_message registration_id, data, collapse_key, delay_while_idle
      rescue InvalidAuthToken => e
        raise e if retried
        @client.auth_token = fetch_auth_token(@email, @passwd, @source, @cache_dir)
        retried = true
        retry
      end
    end
    
    def reflesh_cache token
      if @cache_dir
        File.open(File.join(cache_dir,"auth_token_#{@email}"), "w") do |file|
            file << token
        end
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
    
    def send_messages messages
      succeeded = []
      headers = {'Authorization' => "GoogleLogin auth=#{@auth_token}" }
      http = Net::HTTP.new(host='android.apis.google.com', port=443)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http.start do |http|
        messages.each do |m|
          req = Net::HTTP::Post.new('/c2dm/send', initheader = headers)
          req.set_form_data(m.form_data)
          response = http.request(req)
          if response['Update-Client-Auth']
            # Auth token is getting stale. Update cleint to the new one, and trigger a callback if it exists
            self.auth_token = response['Update-Client-Auth']
          end
          begin
            check_response response
            succeeded.push(m)
          rescue InvalidAuthToken => e
            break
          end
        end
      end
      return succeeded
    end
    
    def send_message registration_id, data, collapse_key=nil, delay_while_idle=false
      return send_messages([Message.new(registration_id, data, collapse_key, delay_while_idle)])
    end
    
    private
    def check_response response
      case response
      when Net::HTTPSuccess
        if response.body =~ /^Error=(.*)$/
          raise_error $1
        elsif response.body =~ /^id=(.*)$/
          return $1
        else
          raise C2DMException.new "Invalid response body: #{response.body}"
        end
      when Net::HTTPForbidden, Net::HTTPUnauthorized
        raise InvalidAuthToken.new "Invalid or expired auth token."
      else
        raise C2DMException.new "Invalid response code: #{response.code}"
      end
    end
    
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
  
  class Message
    def initialize registration_id, data, collapse_key = nil, delay_while_idle = nil
      @registration_id = registration_id
      @data = data
      @collapse_key = collapse_key
      @delay_while_idle = delay_while_idle
      
      # c2dm service will accept any message where the combined length of keys and values is <= 1024
      data_length = C2DM::message_size data
      raise MessageTooBig.new("message length #{data_length} > 1024") if data_length > 1024
    end
    
    def form_data
      form_data = { 
        'registration_id' => @registration_id,
        'collapse_key' => @collapse_key || @data.hash.to_s
      }
      
      form_data['delay_while_idle'] = '1' if @delay_while_idle
      
      @data.each_pair do |key, value|
        form_data["data.#{key}"] = value
      end 
      return form_data
    end
  end
end


