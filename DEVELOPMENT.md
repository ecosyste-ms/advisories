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

The daily jobs in `app.json` import quilt series from Debian trixie and Ubuntu noble, including their security and update pockets. The Homebrew job imports default patch declarations from core formulae and stores platform overrides on the release.

```sh
bundle exec rake patches:sync:debian
bundle exec rake patches:sync:homebrew
bundle exec rake patches:sync:ubuntu
```

Each job skips unchanged releases and attempts up to 200 imports per run. Set `PATCH_SYNC_LIMIT` to change the batch size, or set `PATCH_SYNC_PACKAGE` to a source package name to check one package. Failed imports retain the previous declarations and are eligible for retry on the next run.

Browse `/patches` to see which downstream releases declare a patch. Identical patch files share one SHA-256 page across distributions. The API accepts an upstream PURL at `GET /api/v1/patches` and returns the evidence for each association. An advisory reference records what the maintainer cited. Verifying a shipped artifact requires separate evidence.

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

To generate the similarity index, set `PATCH_CATALOG_DIR` to a local directory and run `ruby script/patch_index/patch_similarity.rb --output "$PATCH_CATALOG_DIR/similarity-pairs.jsonl.gz" BLOB_DIRECTORY`. Input files are named by SHA-256. Rails reads comparison files from that directory, or from `tmp/cache/patch-index/<environment>` by default. Restart the app after replacing a comparison file.
