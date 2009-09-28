set :application, "saml-sinatra"
set :repository,  "svn+ssh://svn.vocel.com/svn/saml-sinatra/trunk"

set :stages, %w(alltel)
require 'capistrano/ext/multistage'

after "deploy", "deploy:cleanup"

set :rails_env, 'production'

namespace(:deploy) do
  desc <<-DESC
  Start/Stop/Restart the glassfish process
  DESC

  task :start, :roles => :app do
     run <<-CMD
       cd #{current_path} &&
       RAILS_ENV=#{rails_env} CLASSPATH=.:java/asf/lib/xercesImpl-2.9.1.jar jruby -S glassfish
     CMD
  end

  task :stop, :roles => :app do
     run <<-CMD
       cd #{current_path} &&
       kill `cat tmp/pids/glassfish-#{rails_env}.pid`
     CMD
  end

  task :restart, :roles => :app do
    stop
    sleep 5
    start
  end

end
