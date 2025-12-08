const { Pool } = require("pg")


const pool = new Pool({
    connectionString: "postgresql://oswin:zMfWYCqEGAhDsQkvak8gglTrGrZhrnc9@dpg-d4ono43e5dus73cdaoo0-a.oregon-postgres.render.com/amandla_ddb",
    
    ssl: {
        require: true,
        rejectUnauthorized: false,
    }
})

pool.on("connect", () => {
    console.log("✅ Connected to Postgres Database")
})

// Test the connection on startup
pool.query("SELECT NOW()", (err, res) => {
    if (err) {
        console.error("❌ Database connection test failed:", err.message)
    } else {
        console.log("✅ Database connection test successful! Server time:", res.rows[0].now)
    }
})

module.exports = pool;
