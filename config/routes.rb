require 'sidekiq/web'
require 'sidekiq_unique_jobs/web'

Sidekiq::Web.use Rack::Auth::Basic do |username, password|
  ActiveSupport::SecurityUtils.secure_compare(::Digest::SHA256.hexdigest(username), ::Digest::SHA256.hexdigest(ENV["SIDEKIQ_USERNAME"])) &
    ActiveSupport::SecurityUtils.secure_compare(::Digest::SHA256.hexdigest(password), ::Digest::SHA256.hexdigest(ENV["SIDEKIQ_PASSWORD"]))
end if Rails.env.production?

Rails.application.routes.draw do
  mount Rswag::Ui::Engine => '/docs'
  mount Rswag::Api::Engine => '/docs'

  mount Sidekiq::Web => "/sidekiq"
  mount PgHero::Engine, at: "pghero"

  namespace :osv, path: 'v1', defaults: { format: :json } do
    post 'query', to: 'query#create'
    post 'querybatch', to: 'querybatch#create'
    get 'vulns/:id', to: 'vulns#show', as: :vuln, id: /[^\/]+/
  end

  namespace :api, :defaults => {:format => :json} do
    namespace :v1 do
      resources :advisories, only: [:index, :show] do
        collection do
          get :packages
          get :lookup
        end
        member do
          get :related_packages
        end
      end
      resources :sources, only: [:index, :show]
    end
  end

  resources :advisories, only: [:index, :show]

  get 'ecosystems', to: 'ecosystems#index', as: 'ecosystems'
  get 'ecosystems/:ecosystem_id', to: 'ecosystems#show', as: 'ecosystem'
  get 'ecosystems/:ecosystem_id/packages', to: 'ecosystems#packages', as: 'ecosystem_packages'
  get 'ecosystems/:ecosystem_id/*package_name', to: 'ecosystems#package', as: 'ecosystem_package', format: false

  get :recent_advisories_data, to: 'advisories#recent_advisories_data'

  get '/batscope', to: 'batscope#index'
  get '/batscope/owners', to: 'batscope#owners'

  resources :exports, only: [:index], path: 'open-data'

  get '/404', to: 'errors#not_found'
  get '/422', to: 'errors#unprocessable'
  get '/500', to: 'errors#internal'

  root "home#index"
end
