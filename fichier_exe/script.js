const canvas = document.getElementById('gameCanvas');
const ctx = canvas.getContext('2d');
const gridSize = 20;
let snake = [{ x: 200, y: 200 }];
let direction = 'right';
let food = { x: 100, y: 100 };

document.addEventListener('keydown', changeDirection);
document.getElementById('upBtn').addEventListener('click', () => setDirection('up'));
document.getElementById('leftBtn').addEventListener('click', () => setDirection('left'));
document.getElementById('rightBtn').addEventListener('click', () => setDirection('right'));
document.getElementById('downBtn').addEventListener('click', () => setDirection('down'));

function gameLoop() {
    moveSnake();
    if (checkCollision()) return;
    drawGame();
    setTimeout(gameLoop, 100);
}

function moveSnake() {
    const head = { ...snake[0] };
    switch (direction) {
        case 'up': head.y -= gridSize; break;
        case 'down': head.y += gridSize; break;
        case 'left': head.x -= gridSize; break;
        case 'right': head.x += gridSize; break;
    }
    snake.unshift(head);
    if (head.x === food.x && head.y === food.y) {
        food = { x: getRandomInt(0, canvas.width / gridSize) * gridSize, y: getRandomInt(0, canvas.height / gridSize) * gridSize };
    } else {
        snake.pop();
    }
}

function checkCollision() {
    const head = snake[0];
    for (let i = 1; i < snake.length; i++) {
        if (snake[i].x === head.x && snake[i].y === head.y) return true;
    }
    return head.x < 0 || head.x >= canvas.width || head.y < 0 || head.y >= canvas.height;
}

function drawGame() {
    ctx.fillStyle = '#2d2d2d';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = '#a7f3d0';
    for (const part of snake) {
        ctx.fillRect(part.x, part.y, gridSize, gridSize);
    }
    ctx.fillStyle = '#ff8906';
    ctx.fillRect(food.x, food.y, gridSize, gridSize);
}

function changeDirection(event) {
    const keyPressed = event.keyCode;
    switch (keyPressed) {
        case 37: setDirection('left'); break;
        case 38: setDirection('up'); break;
        case 39: setDirection('right'); break;
        case 40: setDirection('down'); break;
    }
}

function setDirection(newDirection) {
    const oppositeDirections = {
        'up': 'down',
        'down': 'up',
        'left': 'right',
        'right': 'left'
    };
    if (newDirection !== oppositeDirections[direction]) {
        direction = newDirection;
    }
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min)) + min;
}

gameLoop();