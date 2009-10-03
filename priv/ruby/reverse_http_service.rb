#!/usr/bin/env ruby
#
# First hack at creating a ruby ReverseHTTP client - see http://www.reversehttp.net/
#
# Sean O'Halpin, 2009-10-03
#
# TODO: sort out 'remove_port' issue
# TODO: tidy up/refactor
# TODO: better recovery from failed HTTP requests
# TODO: turn into proper library and separate clients (maybe runner with plugins - cf. mqp)
# TODO: keyword initializers
# TODO: docs

require 'pp'
require 'restclient'
require 'time'
require 'thin'
require 'thin/request'
require 'rack'
require 'base64'

#Thread.abort_on_exception = true
RestClient.log = "stdout"

# if ENV["http_proxy"]
#   RestClient.proxy = ENV["http_proxy"]
# end

# helper to dump contents of request
def dump_request(request)
  if request
    puts [
          [:request, request],
          [:code, request.code],
          [:headers, request.headers],
          [:body, request.to_s],
         ].pretty_inspect
  else
    puts "nil request"
  end
  STDOUT.flush
end

# ReverseHTTP gateway client
module ReverseHTTP
  # Pseudo-server id
  SERVER = "Ruby reversehttp server 0.1"

  # converts Rack style response triplet [status, headers, body] into
  # raw textual representation for sending back to client.
  #
  # usage:
  #   Response.new(status, headers, body).payload
  #
  class Response < ::Thin::Response
    attr_accessor :body

    # takes Rack-style response as input,
    # e.g. Response.new(*rack_handler.call(env))
    def initialize(status, headers, body)
      super()
      self.status = status
      @body = body

      # don't pass on, e.g., "Transfer-Encoding: Chunked" - we already have the complete response
      # and passing this header on results in a zero-length body
      headers.delete(:transfer_encoding)
      #headers["Content-Type"] = headers.delete(:content_type)
      #headers.delete(:set_cookie)
      headers = normalize_headers(headers)
      headers["Content-Length"] = body.to_s.size.to_s
      self.headers = headers
      # maybe do some fixup on body here - don't forget ETag
      puts "RESPONSE HEADERS"
      puts self.head
    end

    # normalize header keys from :content_type to "Content-Type"
    def normalize_headers(headers) # :nodoc:
      headers.inject({ }) { |hash, (key, value)|
        key = key.to_s.downcase.split(/[_\-]/).map{ |s| s.capitalize }.join('-')
        hash[key] = value
        hash
      }
    end

    # raw text of HTTP response
    def payload
      head + body.to_s
    end

    # String representation of the headers to be sent in the response. Overrides Thin::Response#headers_output
    def headers_output
      # Set default headers
      # QUERY: Do I want to bump off Keep-Alive?
      @headers['Connection'] = persistent? ? KEEP_ALIVE : CLOSE
      @headers['Server']     = ReverseHTTP::SERVER
      @headers.to_s
    end
  end

  # converts raw HTTP request string into a request object
  class Request < ::Thin::Request

    # server is ReverseHTTP::Client; raw_body is string (or object
    # responding to #to_s) to parse into request
    #
    # usage: Request.new(reverse_http_server, input_request).env
    def initialize(server, raw_body, &block)
      super()
      parse(raw_body.to_s)
      env["SERVER_SOFTWARE"] = ReverseHTTP::SERVER
      # TODO: use server.location to calculate this properly
      env["reversehttp.path_info"] = env["PATH_INFO"].gsub(%r{^/#{server.name}/}, '')
    end

  end

  # handles creating subscriptions with ReverseHTTP gateway and
  # provides hook to attach services
  class Client
    attr_reader :name
    attr_reader :token
    attr_reader :server_url
    attr_reader :public_url
    attr_reader :private_url
    attr_reader :next_request
    attr_accessor :lease
    attr_accessor :running
    attr_accessor :verbose
    attr_accessor :remove_port

    # name
    # server_url
    # token
    # lease
    #
    # block, if supplied, is a Rack-compatible block, i.e. taking an
    # env hash and returning an array containing [status, headers,
    # body].
    #
    def initialize(*args, &block)
      @verbose = false
      @remove_port = false
      if args.size > 0
        register(*args)
        if block_given?
          serve_forever(&block)
        end
      end
    end

    # parse the link headers returned from the register call
    def parse_link_headers(response)
      result = {}
      response.headers[:link].split(/, /).each do |link_header|
        url = rel = nil
        link_header.split(/;/).each do |piece|
          piece = piece.strip
          if piece[0].chr == "<"
            url = piece[1..-2]
          elsif piece[0..4].downcase == 'rel="'
            rel = piece[5..-2]
          end
        end
        if url and rel
          result[rel] = url
        end
      end
      if @remove_port
        result.each do |key, value|
          result[key] = value.gsub(/:8000/, '')
        end
      end
      #pp [:links, result]
      result
    end
    private :parse_link_headers

    # register namespace with reversehttp gateway
    def register(name, server_url = "http://localhost:8000/reversehttp", token = "-", lease = 30)
      @name = name
      @token = token
      @server_url = server_url
      @lease = lease
      _register
    end

    # do the actual call to the reversehttp gateway to register -
    # split like this so can be called in #fetch_next below
    def _register
      puts "Registering"
      payload = {:name => @name, :token => @token, :lease => @lease }
      # TODO: recovery
      res = RestClient::Request.execute(:method => :post, :url => @server_url, :payload => payload, :raw_response => true)
      #res = RestClient.post(@server_url, payload)
      dump_request(res) if @verbose
      links = parse_link_headers(res)
      #pp [:links, links]
      @next_request = links["first"]
      @public_url = links["related"]
      @private_url = res.headers[:location]
      # reset retry_delay
      @retry_delay = 1
    end
    private :_register

    # reply to caller
    def reply(request, reply_url, &block)
      # send to caller
      RestClient.post(reply_url,
                      ReverseHTTP::Response.new(*block.call(ReverseHTTP::Request.new(self, request).env)).payload,
                      { :content_type => request.headers[:content_type] })
    end

    # fetch next request from gateway
    def fetch_next
      begin
        request = RestClient::Request.execute(:method => :get, :url => @next_request, :raw_response => true)
        puts "SERVE"
        #dump_request(request)
        # TODO: handle other response codes
        while request.code == 204      # timeout
          _register
          request = RestClient::Request.execute(:method => :get, :url => @next_request, :raw_response => true)
          #dump_request(request)
        end
      rescue => e
        puts "Exception in #fetch_next - #{e.class}: #{e}"
        if @retry_delay < 32
          @retry_delay *= 2
        end
        puts "Retry in #{@retry_delay} seconds..."
        sleep @retry_delay
        retry
      end
      req_links = parse_link_headers(request)
      reply_url = @next_request
      @next_request = req_links["next"]
      [request, reply_url]
    end

    # serve a single request, calling block to process it.
    # the block is a Rack-compatible handler
    def serve(&block)
      request, reply_url = fetch_next
      Thread.start {
        begin
          reply(request, reply_url, &block)
        rescue Exception => e
          puts "Exception in #serve replying to client - #{e.class}: #{e}"
        end
      }
    end

    # loop over serve block
    def serve_forever(&block)
      @running = true
      while @running
        serve(&block)
      end
    end

  end
end

# examples of use

# simple Hello World test
def hello(name = "hello")
  client = ReverseHTTP::Client.new(name) do |env|
    # simulate some work...
    #sleep rand(10)
    headers = {
      "Content-type" => "text/plain",
      "Date" => Time.now.httpdate
    }

    body = "Path: #{env["PATH_INFO"]}
Reverse HTTP Path: #{env["reversehttp.path_info"]}

Hello World from #{name} at #{Time.now}

env ------------------------
#{env.pretty_inspect}
----------------------------
"
    headers = { }
    [200, headers, body]
  end
  client
end

# relay HTTP requests
def relay(name = "relay", server_url = "http://localhost:8000/reversehttp", headers = { })
  client = ReverseHTTP::Client.new(name, server_url, "-", 60) do |env|
    begin
      request = RestClient::Request.execute(:method => :get,
                                            :url => env["reversehttp.path_info"],
                                            :headers => headers,
                                            :raw_response => true)
      #dump_request(request)
      [request.code, request.headers, request.to_s]
    rescue RestClient::ResourceNotFound => e
      [404, { }, "Not found\r\n"]
    rescue => e
      [400, { }, e.to_s]
    rescue Exception => e
      # See http://www.ietf.org/rfc/rfc2324.txt
      [418, { }, e.to_s]
    end
  end
  client
end

