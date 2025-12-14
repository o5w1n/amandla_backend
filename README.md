# Amandla - Collaboration Platform

Amandla is a web-based task management and collaboration tool designed for teams. It allows users to create teams, assign tasks, and track progress using a Kanban-style board.

## Tech Stack

### Frontend

- **HTML**: For structure.
- **CSS**: For styling (Custom CSS, Flexbox).
- **JavaScript**: For interactivity and API integration.

### Backend

- **Node.js**: Runtime environment.
- **Express.js**: Web server framework.
- **MongoDB**: Database for storing users, teams, and tasks.

## How to Run

### Backend

1. Navigate to the `backend` folder.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file with your  secret keys (JWT_SECRET).
4. Create a config folder, in it will be a backend.js file which will contain our db link.
5. Start the server:
   ```bash
   nnpm run dev
   ```

### Frontend

1. Navigate to the `frontend` folder.
2. Open `index.html` in your browser.
   - Alternatively, you can use Live Server in VS Code to run it.

## References

### Frontend

1. **HTML5 Drag and Drop API**: Used for the Kanban board drag-and-drop functionality in `ui.js`.
   - [W3Schools Drag and Drop](https://www.w3schools.com/html/html5_draganddrop.asp)
2. **JavaScript Fetch API**: Used for sending requests to the backend (GET, POST, PUT, DELETE) in `api.js`.
   - [MDN Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API/Using_Fetch)
3. **JavaScript Closures and Loops**: Helped fix the issue where the last item was selected in for-loops in `teams.js`.
   - [StackOverflow: Closures in Loops](https://stackoverflow.com/questions/750486/javascript-closure-inside-loops-simple-practical-example)
4. **CSS Flexbox Layout**: Used for the dashboard grid and layout.
   - [CSS Tricks Flexbox Guide](https://css-tricks.com/snippets/css/a-guide-to-flexbox/)
5. **Modal Window Logic**: Adapted for the custom `showmodel` functions.
   - [W3Schools Modals](https://www.w3schools.com/howto/howto_css_modals.asp)
6. **Kanban Board Tutorial**: General logic for moving tasks.
   - [George Francis Kanban Guide](https://georgefrancis.dev/writing/create-a-kanban-board-with-html-css-and-javascript/)

### Backend

1. **Express Routing**: Used for setting up API endpoints in `server.js`.
   - [Express Basic Routing](https://expressjs.com/en/starter/basic-routing.html)
2. **MongoDB & Mongoose Queries**: Used for database operations (`find`, `save`, `findById`).
   - [Mongoose Docs](https://mongoosejs.com/docs/queries.html)
3. **JWT Authentication**: Used for securing routes and handling user login.
   - [JWT.io Introduction](https://jwt.io/introduction)
4. **CORS Middleware**: Needed to allow the frontend to talk to the backend.
   - [Express CORS Middleware](https://expressjs.com/en/resources/middleware/cors.html)
5. **Node.js File System**: General Node.js server setup.
   - [Node.js Docs](https://nodejs.org/en/docs/)

