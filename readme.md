##
![GitHub repo size](https://img.shields.io/github/repo-size/dzenis-h/Bootcamp-API)
![GitHub contributors](https://img.shields.io/github/contributors/dzenis-h/Bootcamp-API)
![GitHub stars](https://img.shields.io/github/stars/dzenis-h/Bootcamp-API?style=social)
![GitHub forks](https://img.shields.io/github/forks/dzenis-h/Bootcamp-API?style=social)
[![LinkedIn Follow](https://img.shields.io/badge/-Follow-blue?style=social&logo=linkedin&link=https://www.linkedin.com/in/dzenis-h/)](https://www.linkedin.com/in/dzenis-h/)
[![GitHub Follow](https://img.shields.io/badge/-Follow-black?style=social&logo=github&link=https://github.com/dzenis-h)](https://github.com/dzenis-h)

##


##  Bootcamp API ![RESTful API](https://img.shields.io/badge/RESTful-API-blue)

## Overview 👀

My Awesome App is a web application that allows users to do awesome things. It is a RESTful API built with Node.js, Express, MongoDB, and Mongoose. It has a responsive and user-friendly interface, and it supports authentication and authorization features. You can see a screenshot of the app below:

![Screenshot](https://drive.google.com/uc?export=view&id=1w981ojQFGlpUQOYrRk5mEzqkD1CvDEtd)



## Tech Stack Used 🛠️

| Tech | Docs | Description |
| ---- | ---- | ----------- |
| ![Node.js](https://img.shields.io/badge/Node.js-43853D?style=flat&logo=node.js&logoColor=white) | [Node.js](https://nodejs.org/en/docs/) | Node.js is a JavaScript runtime environment that executes JavaScript code outside a web browser. |
| ![Express.js](https://img.shields.io/badge/Express.js-000000?style=flat&logo=express&logoColor=white) | [Express.js](https://expressjs.com/en/4x/api.html) | Express.js is a web application framework for Node.js that provides a set of features for web and mobile applications. |
| ![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=flat&logo=mongodb&logoColor=white) | [MongoDB](https://docs.mongodb.com/) | MongoDB is a cross-platform document-oriented database program that uses JSON-like documents with optional schemas. |
| ![Mongoose](https://img.shields.io/badge/Mongoose-880000?style=flat&logoColor=white) | [Mongoose](https://mongoosejs.com/docs/) | Mongoose is an object data modeling (ODM) library for MongoDB and Node.js that provides a schema-based solution to model your application data. |
| ![JSON Web Token](https://img.shields.io/badge/JSON_Web_Token-000000?style=flat&logo=json-web-tokens&logoColor=white) | [JSON Web Token](https://jwt.io/introduction) | JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way of securely transmitting information between parties as a JSON object. |
| ![Bcrypt.js](https://img.shields.io/badge/Bcrypt.js-3385FF?style=flat&logoColor=white) | [Bcrypt.js](https://github.com/dcodeIO/bcrypt.js/blob/master/README.md) | Bcrypt.js is a JavaScript library for hashing and comparing passwords using the bcrypt algorithm. |
| ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat&logo=javascript&logoColor=black) | [JavaScript](https://developer.mozilla.org/en-US/docs/Web/JavaScript) | JavaScript is a scripting or programming language that allows you to implement complex features on web pages. |
| ![Postman](https://img.shields.io/badge/Postman-FF6C37?style=flat&logo=postman&logoColor=white) | [Postman](https://www.postman.com/documentation/) | Postman is a collaboration platform for API development that simplifies each step of building an API and streamlines collaboration. |
| ![REST API](https://img.shields.io/badge/REST_API-02569B?style=flat&logo=rest-api&logoColor=white) | [REST API](https://restfulapi.net/) | REST API (Representational State Transfer Application Programming Interface) is a set of rules that allow programs to talk to each other. The developer creates the API on the server and allows the client to talk to it. |
| ![JSON](https://img.shields.io/badge/JSON-000000?style=flat&logo=json&logoColor=white) | [JSON](https://www.json.org/json-en.html) | JSON (JavaScript Object Notation) is a lightweight data-interchange format that is easy for humans and machines to read and write. |
| ![Firebase](https://img.shields.io/badge/Firebase-FFCA28?style=flat&logo=firebase&logoColor=black) | [Firebase](https://firebase.google.com/docs/) | Firebase is a platform developed by Google for creating mobile and web applications. It provides various services such as authentication, database, storage, hosting, and more. |

## Setup ⚙️

To start using this example:
1. Clone this repo with git clone
2. Install all the dependencies with npm install
3. Create your own credentials (if necessary)
4. Move into the appropriate folder(s)
5. Afterward, just run the start the project

## Usage 📝

This is a RESTful API that follows the CRUD (Create, Read, Update, Delete) operations. It has the following endpoints:

- GET /api/users - returns all the users in the database
- GET /api/users/:id - returns a single user by id
- POST /api/users - creates a new user with the given data
- PUT /api/users/:id - updates an existing user by id with the given data
- DELETE /api/users/:id - deletes an existing user by id

The data for each user should have the following format:

```json
{
  "name": "John Doe",
  "email": "johndoe@example.com",
  "password": "123456",
  "role": "admin"
}
```

You can use Postman to test the API and see the results.

## Contributing 🙌

Contributions are always welcome! If you would like to contribute to this project, please follow these steps:
1. Fork the repository. 🍴
2. Create a new branch. 🌵
3. Make your changes and test them thoroughly. 👨‍💻
4. Submit a pull request. ✔

## License 📑

This project is licensed under the MIT License. This means that you can use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software without any restrictions. For more details, please see the [LICENSE]() file.

## Deployment 🚀

This project is deployed on Firebase. You can access it [here](bootcamp-api-docs.web.app)

## Credits 👨🏻‍💻

This repo was created by [Dzenis H.]()

Contributions are more than welcome. 🫡

If you like what you see, please consider giving a ⭐️
