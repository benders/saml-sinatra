set :application, "saml-sinatra"

default_run_options[:pty] = true
set :repository,  "git@github.com:benders/saml-sinatra.git"
set :scm, "git"
set :branch, "master"
set :user, "alltelportal"
set :deploy_via, :remote_cache

ssh_options[:forward_agent] = true
ssh_options[:user] = "alltelportal"

set :stages, %w(alltel)
require 'capistrano/ext/multistage'

after "deploy", "deploy:cleanup"

set :rails_env, 'production'

set :context_root, "/"
set :jruby_location, "/opt/jruby"
set :gf_port, "7700"

namespace(:deploy) do
  desc <<-DESC
  Start/Stop/Restart the glassfish process
  DESC

  task :start, :roles => :app do
#    cd #{current_path} &&
     run <<-CMD
       CLASSPATH=.:java/asf/lib/xercesImpl-2.9.1.jar #{jruby_location}/bin/jruby -S glassfish --contextroot #{context_root} --port #{gf_port} --environment #{rails_env} -P #{current_path}/tmp/pids/glassfish.pid --daemon --log-level 7 #{release_path}
     CMD
  end

  task :stop, :roles => :app do
     run <<-CMD
       kill `cat #{current_path}/tmp/pids/glassfish.pid`
     CMD
  end

  task :restart, :roles => :app do
    stop
    sleep 5
    start
  end

end
