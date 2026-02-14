export default function handler(req, res) {
  res.status(200).json([
    { id: 1, title: "تيشرت أسود", price: 20 },
    { id: 2, title: "تيشرت أبيض", price: 25 }
  ])
}
