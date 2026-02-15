// Import necessary dependencies
const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// In-memory storage for products and orders
let products = [];
let orders = [];

// API endpoint to get products
app.get('/api/products', (req, res) => {
    res.json(products);
});

// API endpoint to create a new product
app.post('/api/products', (req, res) => {
    const product = req.body;
    products.push(product);
    res.status(201).json(product);
});

// API endpoint to get orders
app.get('/api/orders', (req, res) => {
    res.json(orders);
});

// API endpoint to create a new order
app.post('/api/orders', (req, res) => {
    const order = req.body;
    orders.push(order);
    res.status(201).json(order);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
