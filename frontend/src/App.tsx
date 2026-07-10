import { Route, Routes } from "react-router-dom";
import Home from "./pages/Home";
import History from "./pages/History";
import TaskConsole from "./pages/TaskConsole";

// All pages are self-contained light screens (no shared sidebar shell).
export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/history" element={<History />} />
      <Route path="/tasks/:id" element={<TaskConsole />} />
    </Routes>
  );
}
