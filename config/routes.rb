Rails.application.routes.draw do
  mount Rswag::Ui::Engine => '/docs'
  mount Rswag::Api::Engine => '/docs'
  
  mount PgHero::Engine, at: "pghero"

  namespace :api, :defaults => {:format => :json} do
    namespace :v1 do
      resources :advisories, only: [:index, :show] do
        collection do
          get :packages
          get :lookup
        end
      end
    end
  end

  resources :advisories, only: [:index, :show]

  get :recent_advisories_data, to: 'advisories#recent_advisories_data'

  get '/batscope', to: 'batscope#index'
  get '/batscope/owners', to: 'batscope#owners'

  resources :exports, only: [:index], path: 'open-data'

  get '/404', to: 'errors#not_found'
  get '/422', to: 'errors#unprocessable'
  get '/500', to: 'errors#internal'

  root "home#index"
end
