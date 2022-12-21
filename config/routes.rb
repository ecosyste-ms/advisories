Rails.application.routes.draw do
  mount Rswag::Ui::Engine => '/docs'
  mount Rswag::Api::Engine => '/docs'
  
  mount PgHero::Engine, at: "pghero"

  namespace :api, :defaults => {:format => :json} do
    namespace :v1 do
      resources :advisories, only: [:index, :show]
    end
  end

  resources :advisories, only: [:index, :show]

  resources :exports, only: [:index], path: 'open-data'

  get '/404', to: 'errors#not_found'
  get '/422', to: 'errors#unprocessable'
  get '/500', to: 'errors#internal'

  root "advisories#index"
end
