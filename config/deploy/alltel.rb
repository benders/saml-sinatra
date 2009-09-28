set :deploy_to, "/srv/alltelportal/#{application}"
set :deploy_via, :remote_cache

ssh_options[:forward_agent] = true
ssh_options[:user] = "alltelportal"

set :use_sudo, false

role :app, "fcon.vocel.com"
role :web, "fcon.vocel.com"
role :db,  "fcon.vocel.com", :primary => true
