FROM ruby:3.3.4-slim-bullseye

ENV APP_ROOT /usr/src/app
ENV DATABASE_PORT 5432
WORKDIR $APP_ROOT

# =============================================
# System layer

# Will invalidate cache as soon as the Gemfile changes
COPY Gemfile Gemfile.lock $APP_ROOT/

# * Setup system
# * Install Ruby dependencies
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get -yq dist-upgrade && apt-get install -yq --no-install-recommends \
  curl \
  build-essential \
  libpq-dev \
  tzdata \
  netcat \
  libclang-dev \
  git \
 && gem update --system \
 && gem install bundler foreman \
 && bundle config --global frozen 1 \
 && bundle config set without 'test' \
 && bundle install --jobs 2

RUN curl -fsSL https://deb.nodesource.com/setup_current.x | bash - && \
    apt-get install -y nodejs

# ========================================================
# Application layer

# Copy application code
COPY . $APP_ROOT

# Precompile assets for a production environment.
# This is done to include assets in production images on Dockerhub.
RUN RAILS_ENV=production bundle exec rake assets:precompile

# Startup
CMD ["bin/docker-start"]