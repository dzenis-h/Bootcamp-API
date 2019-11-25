## Usage

Update the config/config.env values with your own.

## Install Dependencies

```
npm install
```

## Run App

```
# Run in dev mode
npm run dev

# Run in prod mode
npm start
```

## Database Seeder

To seed the database with users, bootcamps, courses and reviews with data from the "\_data" folder, run

```
# Import all data
node seeder -i

# Destroy all data
node seeder -d
```
