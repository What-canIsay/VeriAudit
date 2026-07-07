import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Projects from "./pages/Projects";
import TaskConsole from "./pages/TaskConsole";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Projects />} />
        <Route path="/tasks/:id" element={<TaskConsole />} />
      </Routes>
    </Layout>
  );
}
