require 'rubygems'
require 'sinatra'
require 'oauth2'
require 'json'
require 'cgi'
require 'haml'
require 'time'

class HamlRenderer

  def initialize(format = "html")
    @format = format
  end

  def render(opts)
    if (opts.has_key?(:view))
      render_file("views/#{opts[:view]}.#{@format}.haml", opts)
    elsif (opts.has_key?(:partial))
      render_file("views/_#{opts[:partial]}.#{@format}.haml", opts)
    end
  end

  def render_file(file, opts)
    Haml::Engine.new(IO.read(file), :ugly => true).render(self, opts[:locals] || {})
  end

end

class JSONFormatter

  class << self

    def htmlEncode(s)
      CGI::escapeHTML(s)
    end

    def decorateWithSpan(value, className)
      '<span class="' + className + '">' + htmlEncode(value) + '</span>'
    end
    
    def valueToHTML(value)
      output = ""
      if (value.nil?)
        output += decorateWithSpan('null', 'null')
      else
        case value
          when Array
            output += arrayToHTML(value)
          when Hash
            output += objectToHTML(value)
          when Numeric 
            output += decorateWithSpan(value.to_s, 'num')
          when String
            if (value.match(/^(http|https):\/\/[^\s]+$/i))
              output += '<a href="' + value + '">' + htmlEncode(value) + '</a>'
            else
              output += decorateWithSpan('"' + value + '"', 'string')
            end
          when TrueClass
          when FalseClass
            output += this.decorateWithSpan(value, 'bool')
        end
      end
      return output
    end
   
    def arrayToHTML(jsonArray)
      output = '[<ul class="array collapsible">'
      jsonArray.each do |value|
        output += "<li>#{valueToHTML(value)}</li>"
      end
      output += "</ul>]"
      if jsonArray.size == 0
        output = "[ ]"
      end 
      output
    end
    
    def objectToHTML(jsonHash)
      output = '{<ul class="obj collapsible">'
      jsonHash.each do |key, value|
        output += "<li><span class=\"prop\">#{htmlEncode(key)}</span>: #{valueToHTML(value)}</li>"
      end
      output += "</ul>}"
      if jsonHash.size == 0
        output = "{ }"
      end
      output
    end
    
    def jsonToHTML(json, title)
      output = "<div id=\"json\">#{valueToHTML(json)}</div>"
      toHTML(output, title)
    end
    
    def toHTML(content, title)
      output = '<doctype html>' + 
        '<html><head><title>' + title + '</title>'
  style =<<END
  <style>
  body {
    font-family: sans-serif;
  }

  .prop {
    font-weight: bold;
  }

  .null {
    color: red;
  }

  .bool {
    color: blue;
  }

  .num {
    color: blue;
  }

  .string {
    color: green;
    white-space: pre-wrap;
  }

  .collapser {
    position: absolute;
    left: -1em;
    cursor: pointer;
  }

  li {
    position: relative;
  }

  li:after {
    content: ',';
  }

  li:last-child:after {
    content: '';
  }

  #error {
    -moz-border-radius: 8px;
    border: 1px solid #970000;
    background-color: #F7E8E8;
    margin: .5em;
    padding: .5em;
  }

  .errormessage {
    font-family: monospace;  
  }

  #json {
    font-family: monospace;
    font-size: 1.1em;
  }

  ul {
    list-style: none;
    margin: 0 0 0 2em;
    padding: 0;
  }

  h1 {
    font-size: 1.2em;
  }

  </style>
END
      output += style + 
        '</head><body>' +
        content + 
        '</body></html>'
    end

  end

end

class Store

  def initialize
    @cache = {}
  end

  def get(user_hash, key)
    if !@cache.has_key?(user_hash)
      return nil
    end
    @cache[user_hash][key]
  end

  def set(user_hash, key, value)
    if !@cache.has_key?(user_hash)
      @cache[user_hash] = {}
    end
    @cache[user_hash][key] = value
  end

  def has_user?(user_hash)
    @cache.has_key?(user_hash)
  end

end

begin
  config = YAML.load_file('config.yml')
rescue
  puts "Please create a config file"
  puts YAML.dump(:hash_salt => 'Your Hash Salt',
                 :app_key => 'Your Key',
                 :app_secret => 'Your Secret')
  exit 1
end

store = Store.new

set :port, 3030
set :storage, store
set :app_config, config

enable :sessions

def client
  OAuth2::Client.new(settings.app_config[:app_key], settings.app_config[:app_secret], 
                     :site => 'https://graph.facebook.com',
                     :ssl => { :ca_path => "/etc/ssl/certs" })
end

@access_token = nil

get '/auth/facebook' do
  redirect client.web_server.authorize_url(
    :redirect_uri => redirect_uri,
    :scope => 'email,offline_access,read_stream'
  )
end

get '/auth/facebook/callback' do
  access_token = client.web_server.get_access_token(params[:code], :redirect_uri => redirect_uri)
  if (access_token != nil)
    user = JSON.parse(access_token.get('/me'))
    user_id = user['id']
    user_hash = Digest::SHA1.hexdigest("#{settings.app_config[:hash_salt]}+#{user_id}")
    settings.storage.set(user_hash, :access_token, access_token)
    redirect (back || session[:back_url] || "/#{user_hash}/json/me")
  else 
    "Access token failed to load"
  end
end

get '/login' do
  redirect '/auth/facebook'
end

def handle_response(format, graph_url = nil)
  splat = params[:splat].dup
  user_hash = splat.shift
  graph_url ||= "/#{splat.join('/')}"
  back_url = "/" + user_hash + "/" + format + graph_url
  storage = settings.storage
  if (!storage.has_user?(user_hash))
    session[:back_url] = back_url
    redirect '/auth/facebook'
    return
  end
  access_token = storage.get(user_hash, :access_token)
  if (access_token.nil?)
    session[:back_url] = back_url
    redirect '/auth/facebook'
    return
  end
  puts "Cached access token: #{access_token.inspect}"
  puts "Fetching from #{graph_url}"
  body = access_token.get(graph_url)
  puts body
  result = JSON.parse(body)
  if block_given?
    yield(result, splat.join('/'))
  else
    result.inspect
  end
end

get '/*/json/*' do
  handle_response('json') do |output, path|
    JSONFormatter.jsonToHTML(output, "Graph response")
  end
end

get '/*/graph/*' do
  handle_response('graph')
end

get '/*/rss/*' do
  handle_response('rss') do |output, path|
    HamlRenderer.new('rss').render(:view => path, :locals => { :posts => output })
  end
end

get '/*/html/*' do
  handle_response('html') do |output, path|
    HamlRenderer.new.render(:view => path, :locals => { :posts => output })
  end
end

def redirect_uri
  uri = URI.parse(request.url)
  uri.path = '/auth/facebook/callback'
  uri.query = nil
  uri.to_s
end

