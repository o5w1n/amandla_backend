require('dotenv').config();
const express = require('express');
const pool = require('./config/backdb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const bodyParser = require('body-parser')
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3004;

app.use(express.json());
app.use(express.urlencoded({ extended: true }))

app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(cors());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/health", async (req, res) => {
    try {
        await pool.query('SELECT NOW()');
        res.status(200).json({
            status: 'OK',
            timestamp: new Date().toISOString(),
            service: 'Amandla Backend',
            database: 'Connected'
        });
    } catch (error) {
        res.status(500).json({
            status: 'ERROR',
            message: 'Database connection failed',
            error: error.message
        });
    }
});

app.get("/", async (req, res) => {
    res.json({
        message: 'Amandla Backend is running!',
        endpoints: {
            auth: ['/auth/register', '/auth/login'],
            teams: ['/auth/teams', '/auth/team/create', '/auth/team/:id'],
            tasks: ['/auth/team/:teamId/tasks']
        }
    });
});

app.post("/auth/register", async (req, res) => {
    // TODO: implement login
    const { username, email, password } = req.body;

    try {
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const userExist = 'Select * from users where email = $1';
        const existuser = await pool.query(userExist, [email]);

        if (existuser.rows.length > 0) {
            return res.status(400).json({ message: 'The person you tried already exists in out databasee' });
        }

        const saltrounds = 10;
        const hashedpass = await bcrypt.hash(password, saltrounds);


        const insertQuery = 'INSERT INTO users(name, email, password) VALUES($1, $2, $3) RETURNING *';
        const addoutcome = await pool.query(insertQuery, [username, email, hashedpass]);
        const addnewuser = addoutcome.rows[0];
        delete addnewuser.password;

        res.status(201).json({ message: 'The user has been registered sucessfully', user: addnewuser });
    } catch (error) {
        console.error('There was an error during registeration:', error);
        res.status(500).json({ message: 'Server has encountered an error', });
    }
});



app.post('/auth/login', async (req, res) => {
    // TODO: implement login
    // res.json({ message: 'Login endpoint placeholder' });

    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'All fields must be filled' });
        }


        const userExist = 'Select * from users where email = $1';
        const existuser = await pool.query(userExist, [email]);

        if (existuser.rows.length === 0) {
            return res.status(400).json({ message: 'Something went wrong, check your credentials and try again' });
        }

        const user = existuser.rows[0];

        const validpass = await bcrypt.compare(password, user.password)
        if (!validpass) {
            return res.status(400).json({ message: 'Something went wrong, check your credentials and try again' })
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ message: 'Login sucessful, here, have your token', token });
    } catch (err) {
        console.error('Login error detected:', err);
        res.status(500).json({ message: 'ERRRRRRROOOOOOORRRRRRRR‼️‼️‼️‼️‼️', error: err.message })
    }

});




app.post('/auth/team/create', async (req, res) => {
    // TODO


    try {
        const { teamname, memberemail } = req.body;
        const creationtoken = req.headers.authorization?.split(' ')[1];



        if (!teamname || !memberemail || !Array.isArray(memberemail) || !creationtoken) {
            return res.status(400).json({ message: 'Please fill all team fields' });
        }
        const decoded = jwt.verify(creationtoken, process.env.JWT_SECRET);
        const creatorid = decoded.id;


        const checkcreator = await pool.query('Select id, email From users where id = $1', [creatorid]);

        if (checkcreator.rows.length === 0) {
            return res.status(404).json({ message: 'Omo. Creator no dey!!' })
        }

        const creator = checkcreator.rows[0];

        const creatorinTeam = await pool.query('Select * From members where user_id = $1', [creatorid])

        if (creatorinTeam.rows.length > 0) {
            return res.status(400).json({ message: 'Already in a team bro😒, Leave first', });
        }

        const allMails = [creator.email, ...memberemail]
        const uniqueMmails = [...new Set(allMails)];

        console.log('All emails to add:', allMails);

        const useroutcome = await pool.query('Select id, email From users where email = ANY($1)', [uniqueMmails]);


        if (useroutcome.rows.length !== allMails.length) {
            const foundmails = useroutcome.rows.map(u => u.email);
            const missing = allMails.filter(mail => !foundmails.includes(mail));
            return res.status(404).json({ message: 'Cannot find some users', missing: missing });
        }
        const userIds = useroutcome.rows.map(u => u.id);
        const usersInTeams = await pool.query(`SELECT u.email, u.name FROM users u JOIN members m ON u.id = m.user_id WHERE u.id = ANY($1)`, [userIds]);

        if (usersInTeams.rows.length > 0) {
            return res.status(400).json({ message: 'Some of them are already in teams', usersInTeams: usersInTeams.rows });
        }

        const teamoutput = await pool.query('Insert into teams (name, created_by) values ($1, $2) returning id, name, created_at', [teamname, creatorid]);
        const team = teamoutput.rows[0];

        for (const user of useroutcome.rows) {
            const role = user.email === creator.email ? 'creator' : 'member';
            await pool.query('Insert into members (team_id, user_id, role) Values ($1,$2,$3)', [team.id, user.id, role]);

        }

        res.status(201).json({ message: `Team "${teamname}" creation successful`, team: team, totalmembers: useroutcome.rows.length });


    } catch (error) {
        console.error('Erorrrrrrrrrr, Team creation unsuccessful:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token invalid bro' })
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired bro' })
        }

        res.status(500).json({ message: 'Could not create team!!' })
    }

});


app.get('/auth/teams', async (req, res) => {
    try {
        const teams = await pool.query(`Select t.id, t.name, t.created_at, u.name as creator_name, COUNT (m.user_id) as member_count from teams t LEFT JOIN users u ON t.created_by = u.id
            LEFT JOIN members m ON t.id = m.team_id GROUP BY t.id, u.name ORDER BY t.created_at DESC`);
        res.json({ message: 'Teams gotten successfully', teams: teams.rows, total: teams.rows.length });
    } catch (error) {
        console.error('Error getting teams:', error);
        res.status(500).json({ message: ' Failed to retrieve teams' })
    }
});


app.get('/auth/team/myTeams', async (req, res) => {
    // TODO

    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(400).json({ message: 'Please authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userid = decoded.id;

        const userTeams = await pool.query(`
            SELECT t.id, t.name, t.created_at, 
                   u.name as creator_name, 
                   COUNT(DISTINCT m2.user_id) as total_members, 
                   (SELECT COUNT(*) FROM tasks WHERE team_id = t.id) as task_count 
            FROM members m 
            JOIN teams t ON m.team_id = t.id 
            JOIN users u ON t.created_by = u.id
            LEFT JOIN members m2 ON t.id = m2.team_id 
            WHERE m.user_id = $1
            GROUP BY t.id, u.name 
            ORDER BY t.created_at DESC`, [userid]);

        res.json({ message: 'Teams have been retrieved successfully', teams: userTeams.rows, total: userTeams.rows.length })
    } catch (error) {
        console.error('Error retrieving user teams:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token invalid bro' })
        }
        res.status(500).json({ message: 'Could retieve team!!' })
    }
})


app.get('/auth/team/:teamId', async (req, res) => {
    // TODO
    try {
        const { teamId } = req.params;

        const teamoutcome = await pool.query(`SELECT t.id, t.name, t.created_at, u.id as creator_id, u.name as creator_name, u.email as creator_email FROM teams t JOIN users u ON t.created_by = u.id WHERE t.id = $1`, [teamId]);

        if (teamoutcome.rows.length === 0) {
            return res.status(404).json({ message: 'Could not find team' });
        }

        const team = teamoutcome.rows[0];

        const membersoutcome = await pool.query(`SELECT u.id, u.name, u.email, m.role, m.joined_at FROM members m JOIN users u ON m.user_id = u.id WHERE m.team_id = $1 ORDER BY CASE WHEN m.role = 'creator' THEN 1 ELSE 2 END, m.joined_at`, [teamId]);


        const statsoutcome = await pool.query(`SELECT COUNT(DISTINCT m.user_id) as total_members, COUNT(DISTINCT CASE WHEN m.role = 'creator' THEN m.user_id END) as creators_count FROM members m WHERE m.team_id = $1`, [teamId]);

        res.json({ message: 'Team details retrieved successfully', team: { ...team, stats: statsoutcome.rows[0] }, members: membersoutcome.rows, total_members: membersoutcome.rows.length });
    } catch (error) {
        console.error('Error getting Team Details:', error);
        res.status(500).json({ message: 'Failed to retrieve team details' });
    }
});

app.post('/auth/team/:teamId/join', async (req, res) => {
    // TODO
    try {
        const { teamId } = req.params;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userid = decoded.id;

        const checkteam = await pool.query('SELECT id, name FROM teams WHERE id =$1', [teamId]);

        if (checkteam.rows.length === 0) {
            return res.status(404).json({ message: 'Could not find team' });
        }

        const team = checkteam.rows[0];

        const checkuser = await pool.query('SELECT id, name FROM users WHERE id =$1', [userid])

        if (checkuser.rows.length === 0) {
            return res.status(404).json({ message: 'Could not find user' });
        }

        const user = checkuser.rows[0];

        const memberalready = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userid]);

        if (memberalready.rows.length > 0) {
            return res.status(400).json({ message: 'Bro, you are already a membert of "${team.name}"' });
        }

        const inanotherteam = await pool.query('SELECT t.name FROM members m JOIN teams t ON m.team_id = t.id WHERE m.user_id = $1', [userid]);

        if (inanotherteam.rows.length > 0) {
            return res.status(400).json({ message: 'Bro, Your name is already registered in teams "${inanotherteam.rows[0].name}". You need to leave first' });
        }

        await pool.query('INSERT INTO members (team_id, user_id, role) VALUES ($1, $2, $3)', [teamId, userid, 'member']);

        const membercountresult = await pool.query('SELECT COUNT(*) FROM members WHERE team_id = $1', [teamId]);

        res.status(201).json({ message: `Successfully joined team "${team.name}"! 🎉`, team: { id: team.id, name: team.name }, user: { id: user.id, name: user.name, role: 'member' }, total_members: parseInt(membercountresult.rows[0].count) });

    } catch (error) {
        console.error('Error joining team:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Failure in joining team!' });
    }
});

app.post('/auth/team/:teamId/leave', async (req, res) => {


    try {
        const { teamId } = req.params;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userid = decoded.id;

        const checkmembership = await pool.query('SELECT m.role, t.name as team_name FROM members m JOIN teams t ON m.team_id = t.id WHERE m.team_id = $1 AND m.user_id = $2', [teamId, userid]);

        if (checkmembership.rows.length === 0) {
            return res.status(404).json({ message: 'Not a member of this team, Bro ' });
        }

        const { role, team_name } = checkmembership.rows[0];


        if (role === 'creator') {
            return res.status(400).json({ message: 'You are the creator bro, you cannot leave the team. Transfer ownership or delete team instead.' });
        }

        await pool.query('DELETE FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userid]);

        res.json({ message: `You have left team "${team_name}"`, team_id: teamId });

    } catch (error) {
        console.error('Error leaving team:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Failure in leaving team!' });
    }
});


app.post('/auth/team/:teamId/tasks', async (req, res) => {
    // res.json({ message: 'Create task placeholder' });
    try {
        const { teamId } = req.params;
        const { title, description, assignedTo, priority, dueDate } = req.body;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userid = decoded.id;

        if (!title) {
            return res.status(400).json({ meesage: 'The task title is a requirement' });
        }

        const teammembershipp = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userid]);
        if (teammembershipp.rows.length === 0) {
            return res.status(404).json({ message: 'You need to be a member to create tasks bro ' });
        }

        const teamchecking = await pool.query('SELECT id, name FROM teams WHERE id = $1', [teamId]);
        if (teamchecking.rows.length === 0) {
            return res.status(404).json({ message: 'Error: Team not found' });
        }

        if (assignedTo) {
            const checkassignee = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, assignedTo]);

            if (checkassignee.rows.length === 0) {
                return res.status(400).json({ message: ' The assignee has to be a team member.' });
            }
        }

        const taskResult = await pool.query(`INSERT INTO tasks (title, description, team_id, created_by, assigned_to, priority, due_date, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [title, description || null, teamId, userid, assignedTo || null, priority || 'medium', dueDate || null, ' Pending']);

        const task = taskResult.rows[0];

        res.status(201).json({ message: ' Hooray: Task has be created successfully', task: task });

    } catch (error) {
        console.error('Error creating the task:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Could not create task bro' });
    }
});





app.get('/auth/team/:teamId/tasks', async (req, res) => {
    try {
        const { teamId } = req.params;
        const { status, assignedTo, priority } = req.query;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userid = decoded.id;


        const teammembershipp = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userid]);
        if (teammembershipp.rows.length === 0) {
            return res.status(403).json({ message: 'Access Denied. You need to be a member to create tasks bro ' });
        }


        let whereClause = 'WHERE t.team_id = $1';
        const queryParams = [teamId];
        let paramCount = 1;

        if (status) {
            paramCount++
            whereClause += `AND t.status = $${paramCount}`;
            queryParams.push(status)
        }

        if (assignedTo) {
            paramCount++
            whereClause += `AND t.assigned_to = $${paramCount}`;
            queryParams.push(assignedTo)
        }

        if (priority) {
            paramCount++
            whereClause += `AND t.priority = $${paramCount}`;
            queryParams.push(priority)
        }

        const tasksResult = await pool.query(`
            SELECT t.id, t.title, t.description, t.status, t.priority, t.due_date, t.created_at, t.updated_at, creator.id as creator_id, creator.name as creator_name, assignee.id as assignee_id, assignee.name as assignee_name
            FROM tasks t LEFT JOIN users creator ON t.created_by = creator.id LEFT JOIN users assignee ON t.assigned_to = assignee.id ${whereClause}
            ORDER BY CASE t.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, t.created_at DESC`, queryParams);

        const statsResult = await pool.query(`SELECT status, COUNT(*) as count FROM tasks WHERE team_id = $1 GROUP BY status`, [teamId]);

        const statis = {
            total: tasksResult.rows.length,
            byStatus: statsResult.rows.reduce((acc, curr) => {
                acc[row.status] = parseInt(curr.count)
                return acc;
            }, {})
        };

        res.json({ message: 'Task gotten sucessfully', task: tasksResult.rows, stats: statis });
    } catch (error) {
        console.error('Error retrieving tasks:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Could not retrive task bro' });
    }
});


app.get('/auth/team/:teamId/tasks/:taskId', async (req, res) => {
    try {
        const { teamId, taskId } = req.params;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;


        const teammembershipp = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userId]
        );

        if (teammembershipp.rows.length === 0) {
            return res.status(403).json({
                message: 'Access denied. Gotta be a team member first bro.'
            });
        }
        const taskResult = await pool.query(`
            SELECT t.*, creator.name as creator_name, creator.email as creator_email, assignee.name as assignee_name, assignee.email as assignee_email, team.name as team_name FROM tasks t LEFT JOIN users creator ON t.created_by = creator.id LEFT JOIN users assignee ON t.assigned_to = assignee.id
            LEFT JOIN teams team ON t.team_id = team.id WHERE t.id = $1 AND t.team_id = $2`, [taskId, teamId]);

        if (taskResult.rows.length === 0) {
            return res.status(404).json({ message: 'Task not found' });
        }

        res.json({
            message: 'Task retrieved successfully',
            task: taskResult.rows[0]
        });

    } catch (error) {
        console.error('Get task error:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Could not get task' });
    }
});

app.put('/auth/team/:teamId/tasks/:taskId', async (req, res) => {

    try {
        const { teamId, taskId } = req.params;
        const { title, description, status, assignedTo, priority, dueDate } = req.body;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        const teammembershipp = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userId]
        );

        if (teammembershipp.rows.length === 0) {
            return res.status(403).json({ message: 'Access denied. Gotta be a team member first bro.' });
        }

        const checktask = await pool.query('SELECT * FROM tasks WHERE id =$1 AND team_id =$2', [taskId, teamId]);

        if (checktask.rows.length === 0) {
            return res.status(403).json({ message: 'Task not found bro' });
        }

        const task = checktask.rows[0];

        const validstats = ['Pending', 'In Progress', 'Completed'];
        if (status && !validstats.includes(status)) {
            return res.status(400).json({ message: 'Status must be: Pending, In Progress, or Completed' })
        }

        if (assignedTo) {
            const assigneecheck = await pool.query('SELECT * FROM members WHERE team_id =$1 AND user_id = $2', [teamId, assignedTo]);


            if (assigneecheck.rows.length === 0) {
                return res.status(400).json({ message: 'Assignee should be team member bro' })
            }
        }
        const updates = [];
        const values = [];
        let paramCount = 0;

        if (title !== undefined) {
            paramCount++;
            updates.push(`title = $${paramCount}`);
            values.push(title);
        }

        if (description !== undefined) {
            paramCount++;
            updates.push(`description = $${paramCount}`);
            values.push(description);
        }

        if (status !== undefined) {
            paramCount++;
            updates.push(`status = $${paramCount}`);
            values.push(status);
        }

        if (assignedTo !== undefined) {
            paramCount++;
            updates.push(`assigned_to = $${paramCount}`);
            values.push(assignedTo);
        }

        if (priority !== undefined) {
            paramCount++;
            updates.push(`priority = $${paramCount}`);
            values.push(priority);
        }

        if (dueDate !== undefined) {
            paramCount++;
            updates.push(`due_date = $${paramCount}`);
            values.push(dueDate);
        }

        paramCount++;
        updates.push(`updated_at = CURRENT_TIMESTAMP`);

        if (updates.length === 0) {
            return res.status(400).json({ message: 'No fields to update' });
        }

        values.push(taskId, teamId);

        const updatequery = `UPDATE tasks SET ${updates.join(', ')} WHERE id = $${paramCount + 1} AND team_id = $${paramCount + 2} RETURNING *`;

        const updateResult = await pool.query(updatequery, values);
        res.json({ message: 'Task updated successfully!', task: updateResult.rows[0] });

    } catch (error) {
        console.error('Error updating task:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Could not update task' });
    }

});



app.delete('/auth/team/:teamId/tasks/:taskId', async (req, res) => {
    try {
        const { teamId, taskId } = req.params;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;


        const teammembershipp = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userId]);

        if (teammembershipp.rows.length === 0) {
            return res.status(403).json({ message: 'Access denied. You are not a team member.' });
        }


        const checktask = await pool.query(`SELECT t.*, m.role as user_role FROM tasks t LEFT JOIN members m ON t.team_id = m.team_id AND m.user_id = $1 
            WHERE t.id = $2 AND t.team_id = $3`, [userId, taskId, teamId]);

        if (checktask.rows.length === 0) {
            return res.status(404).json({ message: 'Task not located' });
        }

        const task = checktask.rows[0];

        if (task.created_by !== userId && task.user_role !== 'creator') {
            return res.status(403).json({ message: 'Only task creator or team creator can delete this task' });
        }


        await pool.query('DELETE FROM tasks WHERE id = $1 AND team_id = $2', [taskId, teamId]);

        res.json({ message: 'Task deleted successfully', taskId: taskId });

    } catch (error) {
        console.error('Error deleting task:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Could not delete task' });
    }
});


app.post('/auth/team/:teamId/tasks/:taskId/assign', async (req, res) => {
    try {
        const { teamId, taskId } = req.params;
        const { assignedTo } = req.body;
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        if (!assignedTo) {
            return res.status(400).json({ message: 'User ID to assign is required' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;


        const assignermembership = await pool.query('SELECT role FROM members WHERE team_id = $1 AND user_id = $2', [teamId, userId]);

        if (assignermembership.rows.length === 0) {
            return res.status(403).json({ message: 'You must be a team member to assign tasks bro' });
        }


        const assigneemembership = await pool.query('SELECT * FROM members WHERE team_id = $1 AND user_id = $2', [teamId, assignedTo]
        );

        if (assigneemembership.rows.length === 0) {
            return res.status(400).json({ message: 'The assignee shpuld be a team member bro' });
        }

        const checktask = await pool.query('SELECT * FROM tasks WHERE id = $1 AND team_id = $2', [taskId, teamId]);

        if (checktask.rows.length === 0) {
            return res.status(404).json({ message: 'Task not found' });
        }


        const updateResult = await pool.query(`UPDATE tasks SET assigned_to = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 AND team_id = $3 RETURNING *`, [assignedTo, taskId, teamId]);

        const assigneeResult = await pool.query('SELECT name, email FROM users WHERE id = $1', [assignedTo]);

        res.json({ message: 'Task assigned successfully!', task: updateResult.rows[0], assignedTo: assigneeResult.rows[0] });

    } catch (error) {
        console.error('Error assigning task:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Could not assign task' });
    }
});


app.get('/auth/my-tasks', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'Authentication is a requirement' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        // Get tasks assigned to this user across all teams
        const tasksResult = await pool.query(`
            SELECT t.*, team.name as team_name, creator.name as creator_name, assignee.name as assignee_name FROM tasks t JOIN teams team ON t.team_id = team.id 
            LEFT JOIN users creator ON t.created_by = creator.id LEFT JOIN users assignee ON t.assigned_to = assignee.id WHERE t.assigned_to = $1
            ORDER BY CASE t.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, t.due_date ASC NULLS LAST, t.created_at DESC`, [userId]);


        const statsResult = await pool.query(`SELECT status, COUNT(*) as count FROM tasks WHERE assigned_to = $1 GROUP BY status `, [userId]);

        const stats = {
            total: tasksResult.rows.length,
            byStatus: statsResult.rows.reduce((acc, row) => {
                acc[row.status] = parseInt(row.count);
                return acc;
            }, {})
        };

        res.json({ message: 'Your tasks retrieved successfully', tasks: tasksResult.rows, stats: stats });

    } catch (error) {
        console.error('Error getting your tasks:', error);

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token is invalid bro' });
        }

        res.status(500).json({ message: 'Could not get your tasks' });
    }
});


app.listen(PORT, '0.0.0.0', () => {  // Listen on all interfaces
    console.log(`Server running on port ${PORT}`);
});