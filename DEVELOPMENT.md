# Development

## Setup

First things first, you'll need to fork and clone the repository to your local machine.

`git clone https://github.com/ecosyste-ms/advisories.git`

The project uses ruby on rails which have a number of system dependencies you'll need to install.

- [ruby](https://www.ruby-lang.org/en/documentation/installation/)
- [postgresql 14](https://www.postgresql.org/download/)
- [node.js 16+](https://nodejs.org/en/download/)
- [redis](https://redis.io/download/) (for Sidekiq background jobs)

You will then need to set some configuration environment variables. Copy `env.example` to `.env.development` and customise the values to suit your local setup.

Once you've got all of those installed, from the root directory of the project run the following commands:

```
bin/setup
rails server
```

You can then load up [http://localhost:3000](http://localhost:3000) to access the service.

### Background Jobs

Background tasks are handled by [Sidekiq](https://github.com/mperham/sidekiq), the workers live in [app/workers](app/workers/).

Sidekiq is automatically run by `bin/dev`, but if you need to run it manually, run the following command:

`bundle exec sidekiq`

The Sidekiq web interface is available at [http://localhost:3000/sidekiq](http://localhost:3000/sidekiq).

### Docker

Alternatively you can use the existing docker configuration files to run the app in a container.

Run this command from the root directory of the project to start the service.

`docker-compose up --build`

You can then load up [http://localhost:3000](http://localhost:3000) to access the service.

For access the rails console use the following command:

`docker-compose exec app rails console`

Runing rake tasks in docker follows a similar pattern:

`docker-compose exec app rake advisories:sync`

## Importing data

The default set of supported data sources are listed in [db/seeds.rb](db/seeds.rb) and can be automatically enabled with the following rake command:

`rake db:seed`

You can then start syncing data for each source with the following command, this may take a while:

`rake advisories:sync`

### Downstream patches

The daily jobs in `app.json` import the patches that Debian trixie, Ubuntu noble and Homebrew core apply on top of upstream source. Debian and Ubuntu patches come from the quilt series in each source package, including the security and updates pockets. Homebrew patches come from each formula's default `patch` declarations.

```sh
bundle exec rake patches:sync:debian
bundle exec rake patches:sync:homebrew
bundle exec rake patches:sync:ubuntu
```

Each job skips releases it has already seen and attempts up to 200 imports per run, so the first sync of a distribution needs a much larger `PATCH_SYNC_LIMIT`. Set `PATCH_SYNC_PACKAGE` to a source package or formula name to sync one package. A release that fails to parse is recorded with its error and skipped until the distribution publishes it again; set `PATCH_SYNC_RETRY_FAILED=1` to try those again. Download failures are retried on the next run.

Each release stores the upstream repository URL its distribution declares. Looking up a registry package PURL at `/patches` or `GET /api/v1/patches` returns the releases whose repository matches that package's `repository_url`. Identical patch files share one SHA-256 page across distributions.

The importer reads source packages with libarchive and the `xz` command. macOS ships libarchive; on Debian or Ubuntu install `libarchive-tools` and `xz-utils`.

## Tests

The applications tests can be found in [test](test) and use the testing framework [minitest](https://github.com/minitest/minitest).

You can run all the tests with:

`rails test`

## Rake tasks

The applications rake tasks can be found in [lib/tasks](lib/tasks).

You can list all of the available rake tasks with the following command:

`rake -T`

## Deployment

A container-based deployment is highly recommended, we use [dokku.com](https://dokku.com/).
